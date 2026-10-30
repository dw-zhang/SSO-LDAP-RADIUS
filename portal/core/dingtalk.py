"""钉钉扫码登录（OAuth2）与通讯录查询

分工：
  - 钉钉负责「证明你是谁」：用户在钉钉里确认授权，我们只拿到 unionId
  - 本模块再把 unionId 换成企业内部 userid，取出手机号与部门
  - 密码校验完全发生在钉钉自己的页面上，本地不留任何密码

依赖权限（企业内部应用）：
  - 扫码登录：login.dingtalk.com 授权（应用需开启「扫码登录」并配置回调域名）
  - 通讯录：取 userid / 手机号 / 部门（与通讯录同步用的是同一套权限）
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("portal.dingtalk")

AUTH_URL = "https://login.dingtalk.com/oauth2/auth"
API = "https://api.dingtalk.com"
OAPI = "https://oapi.dingtalk.com"


class DingTalkError(Exception):
    """钉钉接口调用失败，message 可直接展示给用户"""


class DingTalk:
    def __init__(self, app_key: str, app_secret: str, redirect_uri: str = "",
                 timeout: int = 10):
        self.app_key = app_key
        self.app_secret = app_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout
        self._token = ""
        self._token_exp = 0.0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- HTTP
    def _request(self, url: str, body: dict | None = None,
                 headers: dict | None = None) -> dict:
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=hdrs,
                                     method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise DingTalkError("钉钉接口返回 HTTP %s：%s" % (exc.code, detail))
        except Exception as exc:
            raise DingTalkError("无法连接钉钉服务器：%s" % exc)
        try:
            return json.loads(raw)
        except ValueError:
            raise DingTalkError("钉钉返回非 JSON：%s" % raw[:200])

    # ---------------------------------------------------------------- 授权
    def auth_url(self, state: str, prompt: str = "consent") -> str:
        """拼出钉钉扫码授权页地址，浏览器直接跳过去"""
        query = urllib.parse.urlencode({
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "client_id": self.app_key,
            "scope": "openid",
            "state": state,
            "prompt": prompt,
        })
        return "%s?%s" % (AUTH_URL, query)

    def exchange_code(self, code: str) -> dict:
        """code -> {unionId, openId, nick, mobile?}"""
        if not code:
            raise DingTalkError("缺少授权码 code")
        d = self._request(API + "/v1.0/oauth2/userAccessToken", {
            "clientId": self.app_key,
            "clientSecret": self.app_secret,
            "code": code,
            "grantType": "authorization_code",
        })
        token = d.get("accessToken")
        if not token:
            raise DingTalkError("换取访问令牌失败：%s" % (d.get("message") or d))
        me = self._request(API + "/v1.0/contact/users/me",
                           headers={"x-acs-dingtalk-access-token": token})
        if not me.get("unionId"):
            raise DingTalkError("未取到 unionId：%s" % (me.get("message") or me))
        return me

    # ---------------------------------------------------------------- 通讯录
    def corp_token(self) -> str:
        """企业内部应用 access_token，本地缓存 100 分钟"""
        with self._lock:
            if self._token and time.time() < self._token_exp:
                return self._token
            q = urllib.parse.urlencode({"appkey": self.app_key,
                                        "appsecret": self.app_secret})
            d = self._request("%s/gettoken?%s" % (OAPI, q))
            if d.get("errcode"):
                raise DingTalkError("获取企业令牌失败：%s %s"
                                    % (d.get("errcode"), d.get("errmsg")))
            self._token = d["access_token"]
            self._token_exp = time.time() + 100 * 60
            return self._token

    def userid_by_unionid(self, unionid: str) -> str:
        d = self._request(
            "%s/topapi/user/getbyunionid?access_token=%s" % (OAPI, self.corp_token()),
            {"unionid": unionid})
        if d.get("errcode"):
            raise DingTalkError("unionId 换 userid 失败：%s %s"
                                % (d.get("errcode"), d.get("errmsg")))
        userid = (d.get("result") or {}).get("userid")
        if not userid:
            raise DingTalkError("该钉钉账号不属于本企业通讯录")
        return userid

    def user_detail(self, userid: str) -> dict:
        """返回 name / mobile / email / dept_id_list / title / active"""
        d = self._request(
            "%s/topapi/v2/user/get?access_token=%s" % (OAPI, self.corp_token()),
            {"userid": userid, "language": "zh_CN"})
        if d.get("errcode"):
            raise DingTalkError("读取员工信息失败：%s %s"
                                % (d.get("errcode"), d.get("errmsg")))
        return d.get("result") or {}

    def dept_names(self) -> dict:
        """部门 id -> 部门名（全量，缓存 10 分钟，量很小）"""
        now = time.time()
        cached = getattr(self, "_dept_cache", None)
        if cached and now < getattr(self, "_dept_exp", 0):
            return cached
        mapping, queue = {}, [1]
        while queue:
            dept_id = queue.pop()
            d = self._request(
                "%s/topapi/v2/department/listsub?access_token=%s"
                % (OAPI, self.corp_token()), {"dept_id": dept_id})
            if d.get("errcode"):
                raise DingTalkError("读取部门失败：%s %s"
                                    % (d.get("errcode"), d.get("errmsg")))
            for item in (d.get("result") or []):
                mapping[item["dept_id"]] = item.get("name", "")
                queue.append(item["dept_id"])
        self._dept_cache = mapping
        self._dept_exp = now + 600
        return mapping

    # ---------------------------------------------------------------- 组合
    def identify(self, code: str) -> dict:
        """code -> 统一身份字典（供 Portal 使用）"""
        me = self.exchange_code(code)
        userid = self.userid_by_unionid(me["unionId"])
        detail = self.user_detail(userid)
        return {
            "userid": userid,
            "unionid": me["unionId"],
            "name": detail.get("name") or me.get("nick") or "",
            "mobile": detail.get("mobile") or me.get("mobile") or "",
            "email": detail.get("email") or "",
            "title": detail.get("title") or "",
            "dept_ids": detail.get("dept_id_list") or [],
            "active": detail.get("active", True),
        }
