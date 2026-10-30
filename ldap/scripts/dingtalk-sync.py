#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手动触发 go-ldap-admin 的钉钉同步（部门 + 人员）

日常由容器内 cron 自动跑（02:30 部门 / 03:30 人员），此脚本用于临时补同步。

依赖：无需第三方库，仅标准库 + 本机 http://127.0.0.1:8889 管理端。
密码来源：/opt/SharkSSO/ldap/.secrets 的 LDAP_ADMIN_PW
（go-ldap-admin 的 admin 账号密码首次启动时即初始化为该值）

退出码：0 成功；1 登录失败或同步接口报错
"""
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8889"
CONF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".secrets")


def read_pw():
    for line in open(CONF, encoding="utf-8"):
        if line.startswith("LDAP_ADMIN_PW="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("未找到 LDAP_ADMIN_PW")


def call(path, data=None, token=None, timeout=1800):
    url = BASE + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body,
                                 method="POST" if data is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            return json.loads(raw)
        except Exception:
            return {"code": e.code, "raw": raw[:300]}


def main():
    pw = read_pw()
    enc = call("/api/base/encryptpwd?passwd=" + urllib.parse.quote(pw))
    if enc.get("code") != 0:
        print("密码加密失败:", enc)
        return 1
    login = call("/api/base/login", {"username": "admin", "password": enc["data"]})
    if login.get("code") != 200:
        print("登录失败:", json.dumps(login, ensure_ascii=False)[:300])
        return 1
    token = login["data"]["token"]
    print("登录成功，token 有效期至", login["data"].get("expires"))

    failed = 0
    for label, path in (("部门同步", "/api/group/syncDingTalkDepts"),
                        ("人员同步", "/api/user/syncDingTalkUsers")):
        t0 = time.time()
        r = call(path, {}, token=token)
        cost = time.time() - t0
        ok = r.get("code") == 0
        print("[%s] %.0fs %s %s" % (label, cost, "成功" if ok else "失败",
                                    json.dumps(r, ensure_ascii=False)[:300] if not ok else ""))
        if not ok:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
