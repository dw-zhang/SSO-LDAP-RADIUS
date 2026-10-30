#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 RADIUS 的 site-default 里插入/更新 Portal 授权通道

用途：身份由 Portal（钉钉扫码）核验后，Portal 用「账号 + 令牌」向 RADIUS
请求 VLAN 授权。RADIUS 看到令牌就跳过密码校验，但仍然执行 ldap 组查询，
因此「部门 -> VLAN」的规则照常生效。

幂等：重复执行只替换标记块之间的内容，不会叠加。
"""
import re
import shutil
import sys
import time

SITE = "/opt/SharkSSO/radius/raddb/site-default"
BEGIN = "\t# === SHARKSSO-PORTAL-BEGIN"
END = "\t# === SHARKSSO-PORTAL-END"

token = sys.argv[1] if len(sys.argv) > 1 else ""
if not token:
    sys.exit("用法: deploy-portal-channel.py <令牌>")

block = "\n".join([
    BEGIN + " （Portal 授权通道，勿手工删改）===",
    "\t# 身份由钉钉扫码核验后，Portal 用「账号 + 下面这个令牌」来取 VLAN 授权。",
    "\t# 命中则跳过密码校验（Auth-Type := Accept），但后面的 ldap 组查询照常执行，",
    "\t# 所以「部门 -> VLAN」规则仍然生效；令牌不匹配则什么都不做，不影响账号密码登录。",
    '\tif (&NAS-Identifier == "portal-server" && &User-Password == "%s") {' % token,
    "\t\tupdate control {",
    "\t\t\t&Auth-Type := Accept",
    "\t\t}",
    "\t}",
    END,
])

with open(SITE, encoding="utf-8") as fh:
    text = fh.read()

shutil.copy2(SITE, "%s.bak.%s" % (SITE, time.strftime("%Y%m%d%H%M%S")))

if BEGIN in text and END in text:
    i = text.rindex("\n", 0, text.index(BEGIN)) + 1
    j = text.index("\n", text.index(END)) + 1
    new = text[:i] + block + "\n" + text[j:]
    action = "已更新"
else:
    lines = text.splitlines()
    # 只在 authorize { ... } 段内找 preprocess，避免误插到 preacct 段
    start = next((k for k, l in enumerate(lines) if l.strip() == "authorize {"), -1)
    if start < 0:
        sys.exit("找不到 authorize 段，未修改")
    end = next((k for k in range(start + 1, len(lines)) if lines[k] == "}"), len(lines))
    pos = next((k for k in range(start, end) if lines[k].strip() == "preprocess"), -1)
    if pos < 0:
        sys.exit("在 authorize 段里找不到 preprocess，未修改")
    lines[pos + 1:pos + 1] = [""] + block.splitlines()
    new = "\n".join(lines) + "\n"
    action = "已插入"

with open(SITE, "w", encoding="utf-8") as fh:
    fh.write(new)

print("%s Portal 授权通道到 %s" % (action, SITE))
for line in new.splitlines():
    if "SHARKSSO-PORTAL" in line or "portal-server" in line:
        print("  " + line.strip())
