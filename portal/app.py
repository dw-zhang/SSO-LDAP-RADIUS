"""Portal 服务器主程序

启动：
    python app.py                 # 读取 config.yaml
    python app.py -c other.yaml   # 指定配置
"""

from __future__ import annotations

import argparse
import functools
import logging
import os
import sys
import threading
import time
import uuid

import yaml
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, url_for)

from core import coa, dingtalk, directory, portal_proto, radius, store

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

CFG: dict = {}
RADIUS_CLIENT: radius.RadiusAuth | None = None
COA_CLIENT: coa.CoAClient | None = None
PORTAL_SRV: portal_proto.PortalServer | None = None
PENDING: dict[str, portal_proto.PendingAuth] = {}
DINGTALK: dingtalk.DingTalk | None = None
DIRECTORY: directory.Directory | None = None
STATES: dict[str, float] = {}          # 扫码登录的 state -> 过期时间，防 CSRF
STATES_TTL = 600

log = logging.getLogger("portal.app")


# ------------------------------------------------------------------ 配置
def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ------------------------------------------------------------------ 模板过滤器
@app.template_filter("ts")
def _fmt_ts(value) -> str:
    try:
        return time.strftime("%m-%d %H:%M", time.localtime(int(value)))
    except (TypeError, ValueError):
        return "-"


@app.template_filter("ts_full")
def _fmt_ts_full(value) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(value)))
    except (TypeError, ValueError):
        return "-"


# ------------------------------------------------------------------ 工具
def client_ip() -> str:
    """取终端 IP。
    优先用 AC 重定向时带的 userip 参数；取不到再退回 remote_addr
    （remote_addr 在 AC 做源地址保持时才是终端真实 IP）。"""
    for key in ("userip", "user_ip", "uip", "clientip"):
        value = request.values.get(key, "").strip()
        if value:
            return value
    return request.remote_addr or ""


def ac_peer() -> tuple | None:
    """AC 的 Portal 协议源地址，从待认证会话里取"""
    item = PENDING.get(client_ip())
    return item.peer if item else None


def safe_redirect_target(raw: str) -> str | None:
    """只允许跳回 http/https 且不带换行的地址，避免开放重定向"""
    if not raw or "\n" in raw or "\r" in raw:
        return None
    if raw.startswith(("http://", "https://")):
        return raw
    return None


def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        cfg = CFG["admin"]
        if not auth or auth.username != cfg["username"] or auth.password != cfg["password"]:
            return Response("需要登录", 401,
                            {"WWW-Authenticate": 'Basic realm="Portal Admin"'})
        return fn(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------ 认证页
@app.get("/")
def index():
    return redirect(url_for("portal_page"))


@app.get("/portal")
def portal_page():
    userip = client_ip()
    ssid = request.args.get("ssid", "")
    mac = request.args.get("mac", "") or request.args.get("usermac", "")
    redirect_url = request.args.get("redirect_url", "") or request.args.get("redirect-url", "")
    online = store.get_online_session(userip) if userip else None
    return render_template(
        "login.html",
        userip=userip,
        ssid=ssid,
        mac=mac,
        redirect_url=redirect_url,
        online=online,
        auth_mode=CFG["auth"].get("mode", "both"),
        dingtalk_ready=bool(DINGTALK),
        portal_name=CFG["portal"].get("name", "无线网络认证"),
    )


@app.post("/login")
def login():
    userip = request.form.get("userip", "").strip() or client_ip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ssid = request.form.get("ssid", "")
    mac = request.form.get("mac", "")
    redirect_url = request.form.get("redirect_url", "")

    if not userip:
        store.add_log("", username, "AUTH", "FAIL", "无法获取终端 IP")
        return render_template("result.html", ok=False, title="无法识别终端",
                               message="没有拿到你的 IP 地址，请断开 WiFi 重连后重试。",
                               back_url=url_for("portal_page"))

    if not username or not password:
        store.add_log(userip, username, "AUTH", "FAIL", "用户名或密码为空")
        return render_template("result.html", ok=False, title="信息不完整",
                               message="请输入完整的账号和密码。",
                               back_url=url_for("portal_page"))

    ok, message, granted = RADIUS_CLIENT.authenticate(
        username, password, userip, ssid=ssid, mac=mac)

    if not ok:
        store.add_log(userip, username, "AUTH", "FAIL", message)
        return render_template("result.html", ok=False, title="认证失败",
                               message=message, back_url=url_for("portal_page"),
                               userip=userip)

    store.add_log(userip, username, "AUTH", "OK", f"ssid={ssid} attrs={granted}")
    session_id = store.open_session(
        username=username, userip=userip, mac=mac, ssid=ssid,
        nasip=CFG["ac"]["nas_ip"], timeout=CFG["auth"]["session_timeout"])

    # ---------- 放行 ----------
    mode = CFG["auth"]["release_mode"]
    released, release_info = False, ""
    if mode in ("portal", "both"):
        if PORTAL_SRV and PORTAL_SRV.aff_ack_auth(userip, ac_peer()):
            released, release_info = True, "Portal-AFF_ACK_AUTH"

    if mode in ("coa", "both"):
        coa_ok, coa_msg = COA_CLIENT.authorize(userip, granted)
        release_info = (release_info + "|" if release_info else "") + f"CoA:{coa_msg}"
        released = released or coa_ok

    if not released:
        log.warning("两种放行方式都未成功 userip=%s info=%s", userip, release_info)
        store.add_log(userip, username, "RELEASE", "FAIL", release_info)
        return render_template(
            "result.html", ok=False, title="认证已通过，但放行失败",
            message="账号验证成功，但通知 AC 放行时出错，请联系管理员检查 Portal 协议配置。",
            detail=release_info, back_url=url_for("portal_page"), userip=userip)

    store.add_log(userip, username, "RELEASE", "OK", release_info)
    RADIUS_CLIENT.accounting(username, userip, session_id, 1, ssid, mac)

    target = safe_redirect_target(redirect_url)
    return render_template(
        "result.html", ok=True, title="连接成功",
        message=f"{username}，你现在可以正常上网了。",
        detail=f"在线时长上限 {CFG['auth']['session_timeout'] // 3600} 小时",
        back_url=url_for("portal_page"), userip=userip,
        continue_url=target, session_id=session_id)


# ------------------------------------------------------------------ 钉钉扫码登录
def _state_new() -> str:
    now = time.time()
    for k, exp in list(STATES.items()):
        if exp < now:
            STATES.pop(k, None)
    state = uuid.uuid4().hex
    STATES[state] = now + STATES_TTL
    return state


def _state_ok(state: str) -> bool:
    if not state:
        return False
    exp = STATES.pop(state, 0)
    return exp > time.time()


def _vlan_of(granted: dict) -> str:
    raw = granted.get("Tunnel-Private-Group-Id")
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    return str(raw or "")


def _release_and_finish(radius_user: str, display: str, userip: str, ssid: str,
                        mac: str, redirect_url: str, granted: dict,
                        extra_detail: str = "") -> str:
    """放行 + 记账 + 渲染结果页（密码登录与钉钉登录共用）"""
    session_id = store.open_session(
        username=radius_user, userip=userip, mac=mac, ssid=ssid,
        nasip=CFG["ac"]["nas_ip"], timeout=CFG["auth"]["session_timeout"])

    mode = CFG["auth"]["release_mode"]
    released, release_info = False, ""
    if mode in ("portal", "both"):
        if PORTAL_SRV and PORTAL_SRV.aff_ack_auth(userip, ac_peer()):
            released, release_info = True, "Portal-AFF_ACK_AUTH"

    if mode in ("coa", "both"):
        coa_ok, coa_msg = COA_CLIENT.authorize(userip, granted)
        release_info = (release_info + "|" if release_info else "") + "CoA:%s" % coa_msg
        released = released or coa_ok

    if not released:
        log.warning("两种放行方式都未成功 userip=%s info=%s", userip, release_info)
        store.add_log(userip, radius_user, "RELEASE", "FAIL", release_info)
        return render_template(
            "result.html", ok=False, title="认证已通过，但放行失败",
            message="身份验证成功，但通知 AC 放行时出错，请联系管理员检查 Portal 协议配置。",
            detail=release_info, back_url=url_for("portal_page"), userip=userip)

    store.add_log(userip, radius_user, "RELEASE", "OK", release_info)
    RADIUS_CLIENT.accounting(radius_user, userip, session_id, 1, ssid, mac)

    vlan = _vlan_of(granted)
    detail_parts = []
    if vlan:
        detail_parts.append("已划入 VLAN %s" % vlan)
    else:
        detail_parts.append("未匹配到部门 VLAN，沿用默认网段")
    if extra_detail:
        detail_parts.append(extra_detail)
    detail_parts.append("在线时长上限 %d 小时" % (CFG["auth"]["session_timeout"] // 3600))

    return render_template(
        "result.html", ok=True, title="连接成功",
        message="%s，你现在可以正常上网了。" % display,
        detail=" · ".join(detail_parts),
        back_url=url_for("portal_page"), userip=userip,
        continue_url=safe_redirect_target(redirect_url), session_id=session_id)


def _login_by_identity(ident: dict, ctx: dict, source: str = "dingtalk") -> str:
    """钉钉身份 -> LDAP 认人 -> RADIUS 判 VLAN -> 放行"""
    userip = (ctx.get("userip") or "").strip() or client_ip()
    ssid = ctx.get("ssid", "")
    mac = ctx.get("mac", "")
    redirect_url = ctx.get("redirect_url", "")

    if not userip:
        store.add_log("", ident.get("name", ""), "SSO", "FAIL", "无法获取终端 IP")
        return render_template("result.html", ok=False, title="无法识别终端",
                               message="没有拿到你的 IP 地址，请断开 WiFi 重连后重试。",
                               back_url=url_for("portal_page"))

    if not DIRECTORY:
        return render_template("result.html", ok=False, title="服务未就绪",
                               message="LDAP 目录未配置，请联系管理员。",
                               back_url=url_for("portal_page"))

    # ---------- 1. 在 LDAP 里认人（手机号优先，其次邮箱、姓名） ----------
    try:
        person = DIRECTORY.find_person(mobile=ident.get("mobile", ""),
                                       email=ident.get("email", ""),
                                       name=ident.get("name", ""))
    except directory.DirectoryError as exc:
        store.add_log(userip, ident.get("name", ""), "SSO", "FAIL", "LDAP: %s" % exc)
        return render_template("result.html", ok=False, title="通讯录查询失败",
                               message=str(exc), detail="请联系 IT 检查 LDAP 目录服务。",
                               back_url=url_for("portal_page"), userip=userip)

    if not person or not person.get("uid"):
        store.add_log(userip, ident.get("name", ""), "SSO", "FAIL",
                      "LDAP 未匹配：mobile=%s name=%s"
                      % (ident.get("mobile", ""), ident.get("name", "")))
        return render_template(
            "result.html", ok=False, title="不在企业通讯录中",
            message="钉钉账号已登录，但通讯录里找不到对应员工。",
            detail="手机号 %s / 姓名 %s。如为新员工，请等通讯录同步后重试（每日 03:30 自动同步）。"
                   % (ident.get("mobile", "") or "—", ident.get("name", "") or "—"),
            back_url=url_for("portal_page"), userip=userip)

    # ---------- 2. 用 Portal 令牌向 RADIUS 要授权（部门 -> VLAN 在那里判） ----------
    token = CFG["radius"].get("portal_token", "")
    ok, msg, granted = RADIUS_CLIENT.authenticate(
        person["uid"], token, userip, ssid=ssid, mac=mac)
    if not ok:
        store.add_log(userip, person["uid"], "SSO", "FAIL", "RADIUS: %s" % msg)
        return render_template(
            "result.html", ok=False, title="准入策略校验失败",
            message="身份已确认（%s），但 RADIUS 未放行。" % person["name"],
            detail=msg, back_url=url_for("portal_page"), userip=userip)

    depts = "、".join(person.get("labels", {}).get(g) or g
                     for g in person.get("groups", [])[:3]) or "未归属部门"
    store.add_log(userip, person["uid"], "SSO", "OK",
                  "source=%s depts=%s attrs=%s" % (source, depts, granted))

    return _release_and_finish(
        radius_user=person["uid"], display=person["name"] or person["uid"],
        userip=userip, ssid=ssid, mac=mac, redirect_url=redirect_url,
        granted=granted, extra_detail="部门：%s" % depts)


@app.get("/auth/dingtalk")
def auth_dingtalk():
    if not DINGTALK:
        return render_template("result.html", ok=False, title="钉钉登录未配置",
                               message="请先在 config.yaml 里填写 dingtalk 段。",
                               back_url=url_for("portal_page"))
    ctx = {
        "userip": client_ip(),
        "ssid": request.args.get("ssid", ""),
        "mac": request.args.get("mac", "") or request.args.get("usermac", ""),
        "redirect_url": request.args.get("redirect_url", ""),
    }
    session["dt_ctx"] = ctx
    return redirect(DINGTALK.auth_url(_state_new()))


@app.get("/auth/dingtalk/callback")
def auth_dingtalk_callback():
    if not DINGTALK:
        abort(503)
    ctx = session.get("dt_ctx") or {}
    if not _state_ok(request.args.get("state", "")):
        return render_template("result.html", ok=False, title="登录已超时",
                               message="这个登录链接已失效，请重新发起。",
                               back_url=url_for("portal_page"))
    code = request.args.get("code", "")
    try:
        ident = DINGTALK.identify(code)
    except dingtalk.DingTalkError as exc:
        store.add_log(ctx.get("userip", ""), "", "SSO", "FAIL", str(exc))
        return render_template("result.html", ok=False, title="钉钉登录失败",
                               message=str(exc), back_url=url_for("portal_page"))
    return _login_by_identity(ident, ctx, source="dingtalk")


@app.get("/auth/dev")
def auth_dev():
    """联调通道：钉钉回调域名还没备案时，用手机号模拟一次扫码登录。
    走的是完全相同的后续流程（LDAP 认人 -> RADIUS 判 VLAN -> 放行）。
    正式上线请在 config.yaml 里把 dingtalk.dev_mode 设为 false。"""
    if not CFG.get("dingtalk", {}).get("dev_mode"):
        abort(404)
    ident = {
        "userid": "", "unionid": "", "name": request.args.get("name", ""),
        "mobile": request.args.get("mobile", ""), "email": request.args.get("email", ""),
        "title": "", "dept_ids": [], "active": True,
    }
    ctx = {
        "userip": client_ip(),
        "ssid": request.args.get("ssid", ""),
        "mac": request.args.get("mac", ""),
        "redirect_url": request.args.get("redirect_url", ""),
    }
    log.warning("联调模式登录 mobile=%s userip=%s", ident["mobile"], ctx["userip"])
    return _login_by_identity(ident, ctx, source="dev")


@app.post("/logout")
def logout():
    userip = request.form.get("userip", "") or client_ip()
    sess = store.get_online_session(userip)
    store.close_session(userip, "user-logout")
    store.add_log(userip, sess["username"] if sess else "", "LOGOUT", "OK", "用户主动下线")
    if sess:
        RADIUS_CLIENT.accounting(sess["username"], userip, sess["session_id"], 2,
                                 sess.get("ssid", ""), sess.get("mac", ""),
                                 int(time.time()) - sess["started_at"])
    return render_template("result.html", ok=True, title="已下线",
                           message="设备已退出认证，如需继续使用请重新连接。",
                           back_url=url_for("portal_page"), userip=userip)


# ------------------------------------------------------------------ 管理后台
@app.get("/admin")
@require_admin
def admin_page():
    keyword = request.args.get("q", "")
    return render_template(
        "admin.html",
        stats=store.stats(),
        sessions=store.online_sessions(),
        logs=store.recent_logs(200, keyword),
        keyword=keyword,
        cfg_summary={
            "radius": f"{CFG['radius']['host']}:{CFG['radius']['auth_port']}",
            "ac": f"{CFG['ac']['nas_ip']} (CoA {CFG['ac']['coa_port']})",
            "mode": CFG["auth"]["release_mode"],
            "portal_udp": CFG["portal"]["protocol_port"],
        },
    )


@app.post("/admin/kick")
@require_admin
def admin_kick():
    session_id = request.form.get("session_id", "")
    userip = request.form.get("userip", "")
    ok, msg = COA_CLIENT.disconnect(userip)
    store.close_session_by_id(session_id, "admin-kick")
    store.add_log(userip, "", "KICK", "OK" if ok else "FAIL", f"admin kick: {msg}")
    return redirect(url_for("admin_page"))


@app.get("/api/stats")
@require_admin
def api_stats():
    return jsonify(store.stats())


@app.get("/api/sessions")
@require_admin
def api_sessions():
    return jsonify(store.online_sessions())


@app.get("/health")
def health():
    ldap_ok, ldap_msg = (DIRECTORY.ping() if DIRECTORY else (False, "未配置"))
    return jsonify({
        "status": "ok",
        "portal_udp": CFG["portal"]["protocol_port"],
        "pending": len(PENDING),
        "radius": CFG["radius"]["host"],
        "auth_mode": CFG["auth"].get("mode", "both"),
        "release_mode": CFG["auth"]["release_mode"],
        "dingtalk": bool(DINGTALK),
        "ldap": {"ok": ldap_ok, "detail": ldap_msg},
    })


# ------------------------------------------------------------------ 后台清理
def reaper() -> None:
    while True:
        time.sleep(30)
        try:
            for sess in store.expired_sessions():
                COA_CLIENT.disconnect(sess["userip"])
                store.close_session(sess["userip"], "timeout")
                store.add_log(sess["userip"], sess["username"], "EXPIRE", "OK", "会话到期")
                log.info("会话到期下线 user=%s ip=%s", sess["username"], sess["userip"])
        except Exception:
            log.exception("清理过期会话失败")


def on_ac_logout(userip: str, reason: str) -> None:
    sess = store.get_online_session(userip)
    store.close_session(userip, "ac-logout")
    store.add_log(userip, sess["username"] if sess else "", "LOGOUT", "OK", reason)


# ------------------------------------------------------------------ 启动
def bootstrap(config_path: str) -> None:
    global CFG, RADIUS_CLIENT, COA_CLIENT, PORTAL_SRV, DINGTALK, DIRECTORY
    CFG = load_config(config_path)
    setup_logging(CFG.get("log_level", "INFO"))
    store.init_db()

    # session 用固定密钥，重启后已发起的扫码流程不会失效
    app.secret_key = (CFG["radius"].get("portal_token")
                      or CFG["portal"].get("shared_key")
                      or os.urandom(24).hex())

    RADIUS_CLIENT = radius.RadiusAuth(
        host=CFG["radius"]["host"],
        secret=CFG["radius"]["secret"],
        nas_ip=CFG["ac"]["nas_ip"],
        auth_port=CFG["radius"]["auth_port"],
        acct_port=CFG["radius"]["acct_port"],
        timeout=CFG["radius"]["timeout"],
        retries=CFG["radius"]["retries"],
    )
    COA_CLIENT = coa.CoAClient(
        nas_ip=CFG["ac"].get("coa_host") or CFG["ac"]["nas_ip"],
        secret=CFG["ac"]["coa_secret"],
        port=CFG["ac"]["coa_port"],
    )
    PORTAL_SRV = portal_proto.PortalServer(
        bind_ip=CFG["portal"]["listen_ip"],
        bind_port=CFG["portal"]["protocol_port"],
        on_logout=on_ac_logout,
        pending=PENDING,
    )
    PORTAL_SRV.start()
    threading.Thread(target=reaper, daemon=True, name="reaper").start()

    # ---------------- 钉钉扫码登录 ----------------
    dt = CFG.get("dingtalk") or {}
    if dt.get("app_key") and "CHANGE_ME" not in str(dt.get("app_key")):
        redirect_uri = dt.get("redirect_uri") or (
            CFG["portal"]["public_url"].rstrip("/") + "/auth/dingtalk/callback")
        DINGTALK = dingtalk.DingTalk(dt["app_key"], dt.get("app_secret", ""),
                                     redirect_uri=redirect_uri)
        log.info("钉钉扫码 -> client_id=%s callback=%s dev_mode=%s",
                 dt["app_key"], redirect_uri, dt.get("dev_mode"))
    else:
        log.warning("钉钉未配置（dingtalk.app_key 仍是占位值），扫码登录不可用")

    # ---------------- LDAP 属性库 ----------------
    ld = CFG.get("ldap") or {}
    if ld.get("uri"):
        DIRECTORY = directory.Directory(
            uri=ld["uri"], bind_dn=ld.get("bind_dn", ""), bind_pw=ld.get("bind_pw", ""),
            people_base=ld.get("people_base", ""), group_base=ld.get("group_base", ""),
            timeout=int(ld.get("timeout", 5)))
        ok, msg = DIRECTORY.ping()
        log.info("LDAP 属性库 -> %s %s", ld["uri"], "连接正常" if ok else "异常: " + msg)

    log.info("RADIUS  -> %s:%d", CFG["radius"]["host"], CFG["radius"]["auth_port"])
    log.info("AC      -> %s (CoA %d)", CFG["ac"]["nas_ip"], CFG["ac"]["coa_port"])
    log.info("登录方式 -> %s / 放行 -> %s",
             CFG["auth"].get("mode", "both"), CFG["auth"]["release_mode"])


def main() -> None:
    parser = argparse.ArgumentParser(description="华为 AC Portal 服务器")
    parser.add_argument("-c", "--config", default=os.path.join(BASE_DIR, "config.yaml"))
    args = parser.parse_args()
    if not os.path.exists(args.config):
        print(f"配置文件不存在: {args.config}", file=sys.stderr)
        sys.exit(1)

    bootstrap(args.config)
    host = CFG["portal"]["listen_ip"]
    port = int(CFG["portal"]["listen_port"])
    log.info("Web 界面 -> http://%s:%d/portal", host, port)
    log.info("管理后台 -> http://%s:%d/admin", host, port)
    app.run(host=host, port=port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
