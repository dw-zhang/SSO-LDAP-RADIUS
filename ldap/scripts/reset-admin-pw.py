#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重置 go-ldap-admin 的 admin 登录密码（仅改数据库校验值，不影响 LDAP 管理员密码）"""
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8889"
NEW_PW = sys.argv[1] if len(sys.argv) > 1 else "CHANGE_ME_LDAPADMIN_UI_PW"
MYSQL = ('docker exec sharksso-ldap-mysql mysql -uroot -pCHANGE_ME_MYSQL_ROOT_PW '
         '-e "{sql}" go_ldap_admin')


def call(path, data=None, timeout=30):
    url = BASE + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if data is not None else "GET")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode(errors="ignore") or "{}")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


# 1. 加密新密码
enc = call("/api/base/encryptpwd?passwd=" + urllib.parse.quote(NEW_PW))
if enc.get("code") != 0:
    print("加密失败:", enc)
    sys.exit(1)
cipher = enc["data"]

# 2. 写回数据库（用参数化不便，这里转义单引号即可；密文只含 base64 字符）
if "'" in cipher:
    print("密文含引号，中止")
    sys.exit(1)
sql = "update users set password='%s' where username='admin';" % cipher
p = sh(MYSQL.format(sql=sql))
if p.returncode != 0:
    print("写库失败:", (p.stderr or p.stdout)[:300])
    sys.exit(1)

# 3. 用新密码走完整登录流程验证
enc2 = call("/api/base/encryptpwd?passwd=" + urllib.parse.quote(NEW_PW))
login = call("/api/base/login", {"username": "admin", "password": enc2["data"]})
print("新密码登录验证:", "成功" if login.get("code") == 200 else login)
print("新密码:", NEW_PW)
