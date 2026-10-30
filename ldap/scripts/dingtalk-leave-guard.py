#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""钉钉离职人员守卫（Go-Ldap-Admin 配套）

原理：钉钉同步只会「新增/更新」，不会自动禁用离职人员。
本脚本对比「钉钉在职名单」与「LDAP 里 ou=people 下的账号」，
把钉钉已不存在的人整体移到 ou=disabled（RADIUS 查询范围之外），
从而实现认证层面彻底阻断。

用法：
  python3 dingtalk-leave-guard.sh --check      # 只检查，列出将被禁用的人（默认）
  python3 dingtalk-leave-guard.sh --apply      # 实际执行禁用

退出码：0 正常；1 钉钉接口异常（不动任何数据，避免误杀）
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(BASE_DIR, "config.yml")
LDAP_CONTAINER = "sharksso-ldap"
BASE_DN = "dc=moying,dc=ai"
PEOPLE_DN = "ou=people," + BASE_DN
DISABLED_DN = "ou=disabled," + BASE_DN
LOG_FILE = os.path.join(BASE_DIR, "logs", "leave-guard.log")
API = "https://oapi.dingtalk.com"


def log(msg):
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def read_secrets():
    """从 config.yml 读 LDAP 管理员口令（按段落限定，避免误读飞书段）"""
    txt = open(CONFIG, encoding="utf-8").read()
    def grab(block, key):
        m = re.search(r"^%s:\n((?:[ \t].*\n|\n)*)" % block, txt, re.M)
        if not m:
            return ""
        seg = m.group(1)
        mm = re.search(r'^\s*%s:\s*"?([^"\n#]*)"?' % key, seg, re.M)
        return mm.group(1).strip() if mm else ""
    return {
        "ldap_admin_dn": grab("ldap", "admin-dn"),
        "ldap_admin_pw": grab("ldap", "admin-pass"),
        "app_key": grab("dingtalk", "app-key"),
        "app_secret": grab("dingtalk", "app-secret"),
    }


def http_json(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def get_token(key, secret):
    d = http_json("%s/gettoken?appkey=%s&appsecret=%s"
                  % (API, urllib.parse.quote(key), urllib.parse.quote(secret)))
    if d.get("errcode"):
        raise RuntimeError("获取 token 失败: %s %s" % (d.get("errcode"), d.get("errmsg")))
    return d["access_token"]


def post_api(path, token, payload):
    url = "%s%s?access_token=%s" % (API, path, token)
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def all_dept_ids(token):
    """递归取全部部门 ID"""
    ids, stack = [], [1]
    while stack:
        cur = stack.pop()
        ids.append(cur)
        d = post_api("/topapi/v2/department/listsub", token, {"dept_id": cur})
        if d.get("errcode"):
            # 60003 等部门不存在错误跳过，但 88/400 这类权限错误要暴露
            if d.get("errcode") in (60003,):
                continue
            raise RuntimeError("取子部门失败 dept=%s: %s %s"
                               % (cur, d.get("errcode"), d.get("errmsg")))
        for sub in d.get("result") or []:
            stack.append(sub["dept_id"])
    return ids


def all_users(token, dept_ids):
    """逐部门分页取用户，返回 [{userid, name, mobile, email}]"""
    seen = {}
    for dept in dept_ids:
        cursor = 0
        while True:
            d = post_api("/topapi/v2/user/list", token,
                         {"dept_id": dept, "cursor": cursor, "size": 100})
            if d.get("errcode"):
                raise RuntimeError("取部门用户失败 dept=%s: %s %s"
                                   % (dept, d.get("errcode"), d.get("errmsg")))
            res = d.get("result") or {}
            for u in res.get("list") or []:
                if u.get("userid"):
                    seen[u["userid"]] = {
                        "userid": u["userid"],
                        "name": u.get("name", ""),
                        "mobile": (u.get("mobile") or "").replace("+86", "").strip(),
                        "email": (u.get("email") or "").strip().lower(),
                    }
            if not res.get("has_more"):
                break
            cursor = res.get("next_cursor")
    return list(seen.values())


def ldap_users(admin_dn, admin_pw):
    """取 ou=people 下所有账号的 uid/mail/mobile

    注意：LDAP 的 uid 是姓名拼音，钉钉 userid 是数字串，两者不能直接比较。
    因此用「手机号 + 邮箱」作为身份比对依据。
    """
    cmd = ["docker", "exec", LDAP_CONTAINER, "ldapsearch", "-x",
           "-H", "ldap://127.0.0.1:389", "-D", admin_dn, "-w", admin_pw,
           "-b", PEOPLE_DN, "-LLL", "(uid=*)", "uid", "mail", "mobile", "displayName"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    users, cur = [], {}
    for line in out.splitlines():
        if line.startswith("uid:: "):
            cur["uid"] = _b64(line[6:])
        elif line.startswith("uid: "):
            cur["uid"] = line[5:].strip()
        elif line.startswith("mail: "):
            cur["mail"] = line[6:].strip().lower()
        elif line.startswith("mobile: "):
            cur["mobile"] = line[8:].replace("+86", "").strip()
        elif line.startswith("displayName:: "):
            cur["name"] = _b64(line[13:])
        elif line.startswith("displayName: "):
            cur["name"] = line[13:].strip()
        elif not line.strip() and cur:
            users.append(cur)
            cur = {}
    if cur:
        users.append(cur)
    return users


def _b64(s):
    try:
        return base64.b64decode(s.strip()).decode("utf-8")
    except Exception:
        return ""


def judge(ldap_list, dt_users):
    """判定离职：手机号与邮箱都不在钉钉在职名单中

    返回 (to_disable, skipped)
      to_disable: 确定已离职，应移出 ou=people
      skipped:    缺少手机号/邮箱，无法判定，保持原样（避免误杀）
    """
    mobiles = {u["mobile"] for u in dt_users if u["mobile"]}
    emails = {u["email"] for u in dt_users if u["email"]}
    to_disable, skipped = [], []
    for u in ldap_list:
        m, e = u.get("mobile", ""), u.get("mail", "")
        if not m and not e:
            skipped.append(u)
            continue
        if (m and m in mobiles) or (e and e in emails):
            continue
        to_disable.append(u)
    return to_disable, skipped


def ensure_disabled_ou(admin_dn, admin_pw):
    ldif = ("dn: %s\nobjectClass: organizationalUnit\nou: disabled\n"
            "description: 钉钉已成离职/删除的账号（禁止认证）\n" % DISABLED_DN)
    p = subprocess.run(["docker", "exec", "-i", LDAP_CONTAINER, "ldapadd",
                        "-x", "-H", "ldap://127.0.0.1:389",
                        "-D", admin_dn, "-w", admin_pw],
                       input=ldif, capture_output=True, text=True, timeout=30)
    if "Already exists" not in (p.stderr or "") and p.returncode != 0:
        log("  提示：创建 ou=disabled 返回 %s（通常已存在）" % (p.stderr or "").strip()[:120])


def disable_user(uid, admin_dn, admin_pw, apply):
    """把用户从 ou=people 移到 ou=disabled（RADIUS 查不到 = 无法认证）"""
    src = "uid=%s,%s" % (uid, PEOPLE_DN)
    dst = "uid=%s,%s" % (uid, DISABLED_DN)
    if not apply:
        log("  [预演] 将禁用: %s  →  %s" % (src, dst))
        return True
    p = subprocess.run(
        ["docker", "exec", "-i", LDAP_CONTAINER, "ldapmodrdn", "-x",
         "-H", "ldap://127.0.0.1:389", "-D", admin_dn, "-w", admin_pw,
         "-r", "-s", dst, src],
        capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        log("  [失败] %s: %s" % (uid, (p.stderr or p.stdout).strip()[:200]))
        return False
    log("  [已禁用] %s" % uid)
    return True


def main():
    apply = "--apply" in sys.argv
    sec = read_secrets()
    if not sec["app_key"] or "xxxx" in sec["app_key"]:
        log("未配置钉钉 app-key，退出（先在 config.yml 的 dingtalk 段填凭据）")
        return 1
    log("=== 开始%s ===" % ("执行" if apply else "预演检查"))
    try:
        token = get_token(sec["app_key"], sec["app_secret"])
        depts = all_dept_ids(token)
        dt_users = all_users(token, depts)
        log("钉钉侧：%d 个部门，%d 名在职人员" % (len(depts), len(dt_users)))
    except Exception as exc:
        log("钉钉接口异常，未改动任何数据：%s" % exc)
        return 1

    ldap_list = ldap_users(sec["ldap_admin_dn"], sec["ldap_admin_pw"])
    log("LDAP 侧：ou=people 下 %d 个账号" % len(ldap_list))
    if not ldap_list:
        log("LDAP 为空，跳过（可能尚未同步）")
        return 0

    missing, skipped = judge(ldap_list, dt_users)
    if skipped:
        log("跳过 %d 个缺少手机号/邮箱、无法判定的账号（不处理，避免误杀）" % len(skipped))
        for u in skipped[:5]:
            log("    ? %s (%s)" % (u.get("uid"), u.get("name", "")))
    if not missing:
        log("结果：无离职残留账号，全部一致 ✓")
        return 0
    log("发现 %d 个钉钉已不存在（离职/删除）的账号：" % len(missing))
    for u in missing:
        log("    - %s %s (mobile=%s mail=%s)"
            % (u.get("uid"), u.get("name", ""), u.get("mobile", ""), u.get("mail", "")))
    if apply:
        ensure_disabled_ou(sec["ldap_admin_dn"], sec["ldap_admin_pw"])
    ok = sum(disable_user(u["uid"], sec["ldap_admin_dn"], sec["ldap_admin_pw"], apply)
             for u in missing)
    log("处理完成：%d/%d %s" % (ok, len(missing), "已禁用" if apply else "预演通过"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
