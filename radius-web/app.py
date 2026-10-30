#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SharkSSO RADIUS Web 管理面板

管理 /opt/SharkSSO/radius 下的 users（账号）与 clients.conf（NAS），
提供在线认证测试（pyrad -> 127.0.0.1:1812）、日志查看与对接指南。

设计原则：
- 无数据库：raddb 文件即数据源，每次写盘前自动备份到 .backups/
- 依赖极简：Flask + pyrad
"""

import json
import os
import re
import secrets as _secrets
import socket
import subprocess
import time
from datetime import datetime
from flask import (Flask, abort, flash, redirect, render_template,
                   request, session, url_for)

from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad import packet

# ---------------------------------------------------------------- 配置
RADDB = os.environ.get("RADDB", "/data/raddb")
LOGDIR = os.environ.get("LOGDIR", "/data/logs")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "CHANGE_ME_PANEL_ADMIN_PW")
SECRET_KEY = os.environ.get("SECRET_KEY", "sharksso-radius-web")
RADIUS_HOST = os.environ.get("RADIUS_HOST", "127.0.0.1")
RADIUS_AUTH_PORT = int(os.environ.get("RADIUS_AUTH_PORT", "1812"))
LOCAL_SECRET = os.environ.get("LOCAL_SECRET", "testing123")  # clients.conf 里 localhost 的密钥

USERS_FILE = os.path.join(RADDB, "users")
CLIENTS_FILE = os.path.join(RADDB, "clients.conf")
SECRET_FILE = os.environ.get("SECRET_FILE", "/data/.secret")
ADMIN_PW_FILE = os.environ.get("ADMIN_PW_FILE", "/data/admin.pw")

# LDAP 对接相关
LDAP_CONF = os.path.join(RADDB, "ldap-mod.conf")
SITE_DEFAULT = os.path.join(RADDB, "site-default")
RADIUS_COMPOSE = os.environ.get(
    "RADIUS_COMPOSE", "/opt/SharkSSO/radius/docker-compose.yml")
RADIUS_CONTAINER = os.environ.get("RADIUS_CONTAINER", "sharksso-radius")
# compose 里 LDAP 挂载行的识别与开关注释前缀
LDAP_MOUNT_LINES = (
    "      - ./raddb/ldap-mod.conf:/opt/etc/raddb/mods-enabled/ldap",
    "      - ./raddb/site-default:/opt/etc/raddb/sites-enabled/default",
)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = 3600 * 8

DICT_PATH = os.environ.get("DICT_PATH", "dictionary")  # pyrad 用的精简字典
ITEM_RE = re.compile(r"^([A-Za-z0-9\-\.]+)\s*([:!+]?[=<>]=?|>=|<=)\s*(.+?)\s*,?\s*$")

VLAN_ATTRS = ("Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id")

_SECRET_BAD = re.compile(r"[ \"'`{};\\#]")   # FreeRADIUS 字面量里必须避免的字符


def _gen_secret() -> str:
    """生成一台设备专用的随机密钥（24 位，字母数字 + - _，FreeRADIUS 字面量安全）"""
    return _secrets.token_urlsafe(18)


def _secret_valid(s: str) -> bool:
    return bool(re.fullmatch(r"[!-~]{8,64}", s)) and not _SECRET_BAD.search(s)


# ---------------------------------------------------------------- 备份
def _backup(path: str) -> None:
    if os.path.exists(path):
        bakdir = os.path.join(os.path.dirname(path), ".backups")
        os.makedirs(bakdir, exist_ok=True)
        dst = os.path.join(bakdir, os.path.basename(path) + "." + time.strftime("%Y%m%d%H%M%S"))
        with open(path, "rb") as f, open(dst, "wb") as g:
            g.write(f.read())
        baks = sorted(f for f in os.listdir(bakdir)
                      if f.startswith(os.path.basename(path) + "."))
        for old in baks[:-30]:
            os.unlink(os.path.join(bakdir, old))


# ---------------------------------------------------------------- users 文件解析
def parse_item(text: str):
    """'Attr = "value"' -> (attr, op, raw_value)"""
    m = ITEM_RE.match(text.strip())
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3).strip()


def _strip_quote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _quote_if_needed(v: str) -> str:
    v = str(v).strip()
    if v and (v[0] in "\"'" or re.fullmatch(r"[A-Za-z0-9\.\-:/]+", v)):
        return v
    return '"%s"' % v


def parse_users(text: str) -> list:
    """解析 FreeRADIUS users 文件 -> [{name, checks:[(a,op,v)], reply:[(a,op,v)]}]"""
    entries = []
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if current:
                entries.append(current)
                current = None
            continue
        if line.lstrip().startswith("#"):
            continue
        if line[:1] in ("\t", " ") and current is not None:
            for part in [p for p in line.strip().split(",") if p.strip()]:
                it = parse_item(part)
                if it:
                    current["reply"].append(it)
        else:
            if current:
                entries.append(current)
            m = re.match(r"^(\S+)\s+(.*)$", line.strip())
            if not m:
                current = {"name": line.strip(), "checks": [], "reply": []}
                continue
            name, rest = m.group(1), m.group(2)
            current = {"name": name, "checks": [], "reply": []}
            for part in [p for p in rest.split(",") if p.strip()]:
                it = parse_item(part)
                if it:
                    current["checks"].append(it)
    if current:
        entries.append(current)
    return entries


def serialize_users(entries: list) -> str:
    out = []
    for e in entries:
        checks = e.get("checks") or []
        reply = e.get("reply") or []
        # 首行：用户名 + check 属性（多个属性之间用逗号分隔）
        if checks:
            parts = ["%s %s %s" % (a, op, _quote_if_needed(v))
                     for a, op, v in checks]
            out.append("%s\t%s" % (e["name"], ",\n\t".join(parts))
                       if len(parts) > 1 else
                       "%s\t%s" % (e["name"], parts[0]))
        else:
            out.append(str(e["name"]))
        # reply 属性：每行一个，非最后一行行尾必须带逗号
        for i, (a, op, v) in enumerate(reply):
            sep = "," if i < len(reply) - 1 else ""
            out.append("\t%s %s %s%s" % (a, op, _quote_if_needed(v), sep))
        out.append("")
    return "\n".join(out)


def load_users() -> list:
    with open(USERS_FILE, encoding="utf-8") as f:
        return parse_users(f.read())


def save_users(entries: list) -> None:
    _backup(USERS_FILE)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        f.write(serialize_users(entries))


def get_password(entry: dict) -> str:
    for a, op, v in entry.get("checks", []):
        if a == "Cleartext-Password":
            return _strip_quote(v)
    return ""


def get_vlan(entry: dict) -> str:
    for a, op, v in entry.get("reply", []):
        if a == "Tunnel-Private-Group-Id":
            return _strip_quote(v)
    return ""


# ---------------------------------------------------------------- clients.conf 解析
def parse_clients(text: str) -> list:
    """clients.conf -> [{name, fields:{k:v}, comments:[...]}]，保持文件顺序"""
    result = []
    pending_comments = []
    current = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if current is None:
                pending_comments.append(stripped)
            continue
        m = re.match(r"^client\s+(\S+)\s*\{$", stripped)
        if m:
            current = {"name": m.group(1), "fields": {},
                       "comments": list(pending_comments)}
            pending_comments = []
            continue
        if stripped == "}" and current is not None:
            result.append(current)
            current = None
            continue
        if current is not None:
            k, _, v = stripped.partition("=")
            current["fields"][k.strip()] = v.strip()
    return result


def serialize_clients(clients: list) -> str:
    out = []
    for c in clients:
        for cm in c.get("comments", []):
            out.append(cm)
        out.append("client %s {" % c["name"])
        for k, v in c["fields"].items():
            out.append("    %s = %s" % (k, v))
        out.append("}")
        out.append("")
    return "\n".join(out)


def load_clients() -> list:
    with open(CLIENTS_FILE, encoding="utf-8") as f:
        return parse_clients(f.read())


def save_clients(clients: list) -> None:
    _backup(CLIENTS_FILE)
    with open(CLIENTS_FILE, "w", encoding="utf-8") as f:
        f.write(serialize_clients(clients))


# ---------------------------------------------------------------- 在线认证测试
def radius_test(username: str, password: str, secret: str) -> dict:
    """向本机 RADIUS 发 Access-Request，返回结果与回包属性"""
    try:
        d = Dictionary(DICT_PATH)
        c = Client(server=RADIUS_HOST, authport=RADIUS_AUTH_PORT,
                   secret=secret.encode(), dict=d, timeout=3, retries=2)
        req = c.CreateAuthPacket(code=packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        req["NAS-IP-Address"] = RADIUS_HOST
        resp = c.SendPacket(req)
        attrs = {}
        for attr in resp.keys():
            try:
                attrs[str(attr)] = [str(v) for v in resp[attr]]
            except Exception:
                attrs[str(attr)] = ["<binary>"]
        return {
            "ok": True,
            "result": {packet.AccessAccept: "Access-Accept（认证通过）",
                       packet.AccessReject: "Access-Reject（认证拒绝）",
                       packet.AccessChallenge: "Access-Challenge"}.get(resp.code,
                                                                       "code=%s" % resp.code),
            "accept": resp.code == packet.AccessAccept,
            "attrs": attrs,
        }
    except Exception as exc:
        return {"ok": False, "result": "测试失败：%s" % exc,
                "accept": False, "attrs": {}}


# ---------------------------------------------------------------- LDAP 配置解析
LDAP_FIELDS = ("server", "identity", "password", "base_dn",
               "user_base_dn", "user_filter",
               "group_base_dn", "group_filter", "membership_attribute")

_LDAP_LINE_RE = {
    "server":        re.compile(r"^(\tserver = ).*$", re.M),
    "identity":      re.compile(r"^(\tidentity = ).*$", re.M),
    "password":      re.compile(r"^(\tpassword = ).*$", re.M),
    "base_dn":       re.compile(r"^(\tbase_dn = ).*$", re.M),
}
_LDAP_BLOCK_RE = {
    "user":  ("user_base_dn", "user_filter", "\tuser {", "\tgroup {"),
    "group": ("group_base_dn", "group_filter", "\tgroup {", "\tclient {"),
}


def _quote_ldap(v: str) -> str:
    v = str(v).strip()
    if v and not re.fullmatch(r"[A-Za-z0-9_\$\{\}\.\-/]+", v):
        return "'%s'" % v
    return v or "''"


def _norm(v: str) -> str:
    """比较用：忽略包裹引号差异"""
    return _strip_quote(str(v).strip())


def _block_span(text: str, start_marker: str, end_marker: str):
    i = text.index(start_marker)
    j = text.index(end_marker, i + len(start_marker))
    return i, j


def parse_ldap_conf(text: str) -> dict:
    d = {k: "" for k in LDAP_FIELDS}
    for key, rx in _LDAP_LINE_RE.items():
        m = rx.search(text)
        if m:
            d[key] = _strip_quote(m.group(0).split("=", 1)[1].strip())
    for block, (bd_key, f_key, start_m, end_m) in _LDAP_BLOCK_RE.items():
        try:
            i, j = _block_span(text, start_m, end_m)
            seg = text[i:j]
            m = re.search(r"^\t\tbase_dn = (.*)$", seg, re.M)
            if m:
                d[bd_key] = _strip_quote(m.group(1).strip())
            m = re.search(r"^\t\tfilter = (.*)$", seg, re.M)
            if m:
                d[f_key] = _strip_quote(m.group(1).strip())
        except ValueError:
            pass
    m = re.search(r"^\t\tmembership_attribute = (.*)$", text, re.M)
    if m:
        d["membership_attribute"] = _strip_quote(m.group(1).strip())
    return d


def update_ldap_conf(text: str, values: dict) -> str:
    """只改值有变化的行，其余内容（含注释、引号风格）原样保留"""
    current = parse_ldap_conf(text)
    for key, rx in _LDAP_LINE_RE.items():
        if key in values and values[key] and _norm(values[key]) != _norm(current.get(key)):
            text = rx.sub(lambda m: m.group(1) + _quote_ldap(values[key]),
                          text, count=1)
    for block, (bd_key, f_key, start_m, end_m) in _LDAP_BLOCK_RE.items():
        try:
            i, j = _block_span(text, start_m, end_m)
        except ValueError:
            continue
        seg = text[i:j]
        if values.get(bd_key) and _norm(values[bd_key]) != _norm(current.get(bd_key)):
            seg = re.sub(r"^(\t\tbase_dn = ).*$",
                         lambda m: m.group(1) + _quote_ldap(values[bd_key]),
                         seg, count=1, flags=re.M)
        if values.get(f_key) and _norm(values[f_key]) != _norm(current.get(f_key)):
            seg = re.sub(r"^(\t\tfilter = ).*$",
                         lambda m: m.group(1) + _quote_ldap(values[f_key]),
                         seg, count=1, flags=re.M)
        text = text[:i] + seg + text[j:]
    if values.get("membership_attribute") and \
            _norm(values["membership_attribute"]) != _norm(current.get("membership_attribute")):
        text = re.sub(
            r"^(\t\tmembership_attribute = ).*$",
            lambda m: m.group(1) + _quote_ldap(values["membership_attribute"]),
            text, count=1, flags=re.M)
    return text


def load_ldap_conf() -> dict:
    with open(LDAP_CONF, encoding="utf-8") as f:
        text = f.read()
    d = parse_ldap_conf(text)
    d["_raw"] = text
    return d


def save_ldap_conf(values: dict) -> None:
    with open(LDAP_CONF, encoding="utf-8") as f:
        text = f.read()
    _backup(LDAP_CONF)
    with open(LDAP_CONF, "w", encoding="utf-8") as f:
        f.write(update_ldap_conf(text, values))


def ldap_conf_incomplete(d: dict) -> list:
    """返回仍带 CHANGE_ME 占位的字段列表"""
    bad = []
    for k in ("server", "identity", "password", "base_dn"):
        if not d.get(k) or "CHANGE_ME" in str(d.get(k, "")):
            bad.append(k)
    return bad


# ---------------------------------------------------------------- LDAP 连通性测试
def ldap_probe(d: dict, with_groups: bool = True) -> dict:
    """真实测试：TCP 连通 -> bind -> 搜索组列表"""
    r = {"steps": [], "ok": False, "groups": None}
    server = (d.get("server") or "").strip()
    m = re.match(r"ldap[s]?://\[?([0-9a-zA-Z\.\-]+)\]?(?::(\d+))?", server)
    if not m:
        r["steps"].append(("解析 server 地址", False,
                           "无法从 %r 解析主机（支持 ldap://host[:port]）" % server))
        return r
    host, port = m.group(1), int(m.group(2) or (636 if "ldaps" in server else 389))
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.close()
        r["steps"].append(("TCP 连通 %s:%s" % (host, port), True,
                           "%.0f ms" % ((time.time() - t0) * 1000)))
    except Exception as exc:
        r["steps"].append(("TCP 连通 %s:%s" % (host, port), False, str(exc)))
        return r
    try:
        from ldap3 import Server, Connection, ALL
    except ImportError:
        r["steps"].append(("ldap3 库", False, "容器内未安装 ldap3"))
        return r
    uri = d.get("server") or "ldap://%s:%s" % (host, port)
    t0 = time.time()
    try:
        srv = Server(uri, get_info=ALL, connect_timeout=4)
        conn = Connection(srv, user=d.get("identity") or None,
                          password=d.get("password") or None,
                          auto_bind=True, receive_timeout=6)
    except Exception as exc:
        r["steps"].append(("管理员 bind（%s）" % (d.get("identity") or "匿名"),
                           False, str(exc)))
        return r
    r["steps"].append(("管理员 bind（%s）" % (d.get("identity") or "匿名"), True,
                       "%.0f ms" % ((time.time() - t0) * 1000)))
    base = d.get("base_dn") or ""
    try:
        # 基础 DN 校验
        conn.search(base, "(objectClass=*)", search_scope="BASE",
                    attributes=["dn"], size_limit=1)
        r["steps"].append(("base_dn 校验（%s）" % base, conn.result["description"] in ("success", "success (0)"), conn.result["description"]))
    except Exception as exc:
        r["steps"].append(("base_dn 校验（%s）" % base, False, str(exc)))
    if with_groups:
        gbase = (d.get("group_base_dn") or "ou=groups").replace(
            "${..base_dn}", base).strip(",")
        gbase = gbase if gbase.startswith(base) or not base else "%s,%s" % (gbase, base)
        gfilter = d.get("group_filter") or "(objectClass=groupOfNames)"
        try:
            conn.search(gbase, gfilter, attributes=["cn"], size_limit=200)
            groups = sorted({e.cn.value for e in conn.entries if e.cn.value})
            r["groups"] = groups
            r["steps"].append(("组搜索（%s，%s）" % (gbase, gfilter),
                               True, "找到 %d 个组" % len(groups)))
        except Exception as exc:
            r["steps"].append(("组搜索（%s）" % gbase, False, str(exc)))
    try:
        conn.unbind()
    except Exception:
        pass
    r["ok"] = all(ok for _, ok, _ in r["steps"])
    return r


# ---------------------------------------------------------------- compose 启停
def compose_read() -> str:
    with open(RADIUS_COMPOSE, encoding="utf-8") as f:
        return f.read()


def compose_write(text: str) -> None:
    _backup(RADIUS_COMPOSE)
    with open(RADIUS_COMPOSE, "w", encoding="utf-8") as f:
        f.write(text)


def ldap_compose_enabled(text: str) -> bool:
    lines = text.splitlines()
    for mount in LDAP_MOUNT_LINES:
        # 存在一条未注释的挂载行即视为已启用
        if not any(l.lstrip().startswith(mount.strip())
                   for l in lines if not l.lstrip().startswith("#")):
            return False
    return True


def compose_set_ldap(text: str, enabled: bool) -> str:
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        core = stripped.split("#")[0].strip()
        if any(core == m for m in LDAP_MOUNT_LINES):
            if enabled and stripped.startswith("#"):
                line = "      " + stripped.lstrip("# ")
            elif not enabled and not stripped.startswith("#"):
                line = "      # " + stripped + "   # LDAP 接通后放开"
        out.append(line)
    return "\n".join(out) + "\n"


def compose_apply(text_hint: str = "") -> tuple:
    """docker compose up -d 重建 RADIUS 容器，返回 (ok, output)"""
    try:
        p = subprocess.run(
            ["docker", "compose", "-f", RADIUS_COMPOSE, "up", "-d"],
            capture_output=True, text=True, timeout=180)
        return p.returncode == 0, (p.stdout + p.stderr).strip()[-2000:]
    except Exception as exc:
        return False, str(exc)


def radius_container_status() -> dict:
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f",
             "{{.State.Status}} RestartCount={{.RestartCount}}",
             RADIUS_CONTAINER],
            capture_output=True, text=True, timeout=15)
        out = p.stdout.strip()
        if p.returncode != 0:
            return {"running": False, "detail": "容器不存在"}
        status = out.split()[0] if out else "?"
        return {"running": status == "running", "status": status, "detail": out}
    except Exception as exc:
        return {"running": False, "detail": str(exc)}


def compose_healthy(wait: int = 15) -> bool:
    """要求容器在 ~20 秒窗口内持续 running（排除 LDAP 连不上导致的崩溃循环）"""
    time.sleep(6)
    deadline = time.time() + wait
    while time.time() < deadline:
        st = radius_container_status()
        if not st.get("running"):
            return False
        time.sleep(2)
    return radius_container_status().get("running", False)


# ---------------------------------------------------------------- 登录
@app.before_request
def check_login():
    if request.endpoint not in ("login", "static") and not session.get("authed"):
        return redirect(url_for("login", next=request.path))
    return None


def admin_password() -> str:
    """登录密码：密码文件（面板可改）优先，回退到 compose 环境变量"""
    try:
        with open(ADMIN_PW_FILE, encoding="utf-8") as f:
            pw = f.read().strip()
        if pw:
            return pw
    except OSError:
        pass
    return ADMIN_PASSWORD


@app.route("/password", methods=["GET", "POST"])
def password_page():
    """修改面板登录密码（写入密码文件，即时生效，无需重启面板）"""
    if request.method == "POST":
        cur = request.form.get("cur", "")
        p1 = request.form.get("p1", "")
        p2 = request.form.get("p2", "")
        if cur != admin_password():
            flash("当前密码不正确", "error")
        elif len(p1) < 8:
            flash("新密码至少 8 位", "error")
        elif p1 != p2:
            flash("两次输入的新密码不一致", "error")
        else:
            try:
                with open(ADMIN_PW_FILE, "w", encoding="utf-8") as f:
                    f.write(p1)
                os.chmod(ADMIN_PW_FILE, 0o600)
                flash("面板登录密码已修改，下次登录请用新密码（当前会话不受影响）", "ok")
            except OSError as exc:
                flash("写入密码文件失败：%s" % exc, "error")
        return redirect(url_for("password_page"))
    from_file = admin_password() != ADMIN_PASSWORD
    return render_template("password.html", from_file=from_file)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if request.form.get("password", "") == admin_password():
            session["authed"] = True
            session.permanent = True
            nxt = request.args.get("next") or url_for("dashboard")
            if not str(nxt).startswith("/"):
                nxt = url_for("dashboard")
            return redirect(nxt)
        error = "密码错误"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- 视图
@app.route("/")
def dashboard():
    users = load_users()
    clients = load_clients()
    svc = radius_test("testuser", "TestUser@Example1", LOCAL_SECRET)
    return render_template("dashboard.html", users=users, clients=clients,
                           svc=svc, logs=_list_logs(),
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


@app.route("/users", methods=["GET"])
def users_page():
    rows = []
    for i, e in enumerate(load_users()):
        rows.append({
            "idx": i, "name": e["name"],
            "password": get_password(e),
            "vlan": get_vlan(e),
            "checks": e.get("checks", []),
            "reply": e.get("reply", []),
        })
    return render_template("users.html", rows=rows)


@app.route("/users/add", methods=["POST"])
def users_add():
    name = request.form.get("name", "").strip()
    password = request.form.get("password", "").strip()
    if not name or not password:
        flash("用户名和密码不能为空", "error")
        return redirect(url_for("users_page"))
    entries = load_users()
    if any(e["name"] == name for e in entries):
        flash("用户 %s 已存在" % name, "error")
        return redirect(url_for("users_page"))
    e = {"name": name,
         "checks": [("Cleartext-Password", ":=", '"%s"' % password)],
         "reply": []}
    if request.form.get("enable_vlan"):
        vlan = request.form.get("vlan", "").strip()
        if vlan.isdigit():
            e["reply"] += [("Tunnel-Type", "=", "VLAN"),
                           ("Tunnel-Medium-Type", "=", "IEEE-802"),
                           ("Tunnel-Private-Group-Id", "=", '"%s"' % vlan)]
        else:
            flash("VLAN 号必须是数字，动态 VLAN 未启用", "error")
    if request.form.get("reply_message", "").strip():
        e["reply"].append(("Reply-Message", "=",
                           '"%s"' % request.form["reply_message"].strip()))
    entries.append(e)
    save_users(entries)
    _reload_hint()
    flash("用户 %s 已添加%s" % (name,
          "（动态 VLAN %s）" % get_vlan(e) if get_vlan(e) else ""), "ok")
    return redirect(url_for("users_page"))


@app.route("/users/<int:idx>/edit", methods=["GET", "POST"])
def users_edit(idx: int):
    entries = load_users()
    if idx < 0 or idx >= len(entries):
        abort(404)
    e = entries[idx]
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        vlan = request.form.get("vlan", "").strip()
        enable_vlan = bool(request.form.get("enable_vlan"))
        e["checks"] = ([("Cleartext-Password", ":=", '"%s"' % password)]
                       if password else [])
        reply = [it for it in e.get("reply", [])
                 if it[0] not in VLAN_ATTRS + ("Reply-Message",)]
        if enable_vlan and vlan.isdigit():
            reply += [("Tunnel-Type", "=", "VLAN"),
                      ("Tunnel-Medium-Type", "=", "IEEE-802"),
                      ("Tunnel-Private-Group-Id", "=", '"%s"' % vlan)]
        if request.form.get("reply_message", "").strip():
            reply.append(("Reply-Message", "=",
                          '"%s"' % request.form["reply_message"].strip()))
        e["reply"] = reply
        save_users(entries)
        _reload_hint()
        flash("用户 %s 已更新" % e["name"], "ok")
        return redirect(url_for("users_page"))
    return render_template("user_form.html", idx=idx, e=e,
                           password=get_password(e), vlan=get_vlan(e),
                           has_vlan=any(it[0] == "Tunnel-Private-Group-Id"
                                        for it in e.get("reply", [])))


@app.route("/users/<int:idx>/delete", methods=["POST"])
def users_delete(idx: int):
    entries = load_users()
    if 0 <= idx < len(entries):
        name = entries[idx]["name"]
        del entries[idx]
        save_users(entries)
        _reload_hint()
        flash("用户 %s 已删除" % name, "ok")
    return redirect(url_for("users_page"))


# ---------------------------------------------------------------- clients
@app.route("/clients", methods=["GET"])
def clients_page():
    return render_template("clients.html", clients=load_clients())


@app.route("/clients/add", methods=["POST"])
def clients_add():
    name = request.form.get("name", "").strip()
    ipaddr = request.form.get("ipaddr", "").strip()
    secret = request.form.get("secret", "").strip()
    generated = False
    if not (name and ipaddr):
        flash("名称、IP/网段不能为空", "error")
        return redirect(url_for("clients_page"))
    if not secret:
        secret, generated = _gen_secret(), True
    elif not _secret_valid(secret):
        flash("密钥格式不合规：8~64 位可见字符，不能含空格、引号、花括号、分号、反斜杠、#", "error")
        return redirect(url_for("clients_page"))
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+/\d+", ipaddr) and ipaddr.endswith("/16"):
        flash("不建议添加 /16 这类大网段 —— 每台设备一条、独立密钥，避免一台泄露全局遭殃", "warn")
    clients = load_clients()
    if any(c["name"] == name for c in clients):
        flash("client %s 已存在" % name, "error")
        return redirect(url_for("clients_page"))
    clients.append({
        "name": name,
        "fields": {"ipaddr": ipaddr, "secret": secret,
                   "require_message_authenticator": "no", "nas_type": "other"},
        "comments": [],
    })
    save_clients(clients)
    _reload_hint()
    if generated:
        flash("NAS %s（%s）已添加，独立密钥：%s —— 立即填到设备侧 radius-server shared-key"
              % (name, ipaddr, secret), "ok")
    else:
        flash("NAS %s（%s）已添加" % (name, ipaddr), "ok")
    return redirect(url_for("clients_page"))


@app.route("/clients/<name>/rotate", methods=["POST"])
def clients_rotate(name: str):
    """为单台设备换一把新的独立密钥"""
    clients = load_clients()
    tgt = next((c for c in clients if c["name"] == name), None)
    if tgt is None:
        flash("client %s 不存在" % name, "error")
        return redirect(url_for("clients_page"))
    new = _gen_secret()
    tgt["fields"]["secret"] = new
    save_clients(clients)
    _reload_hint()
    flash("NAS %s 的新密钥：%s —— 立即同步到该设备的 radius-server shared-key，"
          "其他设备不受影响" % (name, new), "ok")
    return redirect(url_for("clients_page"))


@app.route("/clients/<name>/delete", methods=["POST"])
def clients_delete(name: str):
    if name == "localhost":
        flash("localhost 是本机自测通道，不允许删除", "error")
        return redirect(url_for("clients_page"))
    clients = [c for c in load_clients() if c["name"] != name]
    save_clients(clients)
    _reload_hint()
    flash("NAS %s 已删除" % name, "ok")
    return redirect(url_for("clients_page"))


# ---------------------------------------------------------------- 测试 / 日志 / 指南
@app.route("/test", methods=["GET", "POST"])
def test_page():
    result = None
    d = {"username": "", "password": "", "secret": LOCAL_SECRET}
    if request.method == "POST":
        d["username"] = request.form.get("username", "").strip()
        d["password"] = request.form.get("password", "")
        d["secret"] = request.form.get("secret", LOCAL_SECRET).strip() or LOCAL_SECRET
        result = radius_test(d["username"], d["password"], d["secret"])
    return render_template("test_auth.html", result=result, d=d)


def _list_logs() -> list:
    logs = []
    if os.path.isdir(LOGDIR):
        for f in sorted(os.listdir(LOGDIR)):
            p = os.path.join(LOGDIR, f)
            if os.path.isfile(p):
                st = os.stat(p)
                logs.append({"name": f, "size": st.st_size,
                             "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%m-%d %H:%M")})
    return logs


@app.route("/logs")
@app.route("/logs/<name>")
def logs_page(name=None):
    logs = _list_logs()
    content = ""
    if name and name in {l["name"] for l in logs}:
        with open(os.path.join(LOGDIR, name), encoding="utf-8", errors="replace") as f:
            content = f.read()[-8000:]
    elif not name and logs:
        return redirect(url_for("logs_page", name=logs[-1]["name"]))
    return render_template("logs.html", logs=logs, name=name, content=content)


@app.route("/config")
def config_page():
    """配置文件展示：按设备的独立密钥表 + users + clients.conf 原文"""
    secret_rows = [{"name": c["name"],
                    "ip": c["fields"].get("ipaddr", "-"),
                    "secret": c["fields"].get("secret", "-")}
                   for c in load_clients()]

    def _read(path):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except OSError as exc:
            return "（无法读取：%s）" % exc

    return render_template("config.html", secret_rows=secret_rows,
                           users_raw=_read(USERS_FILE),
                           clients_raw=_read(CLIENTS_FILE))


# ---------------------------------------------------------------- LDAP 对接
@app.route("/ldap", methods=["GET"])
def ldap_page():
    d = load_ldap_conf()
    compose = compose_read()
    return render_template("ldap.html", d=d,
                           enabled=ldap_compose_enabled(compose),
                           incomplete=ldap_conf_incomplete(d),
                           container=radius_container_status(),
                           site_ok=_site_has_ldap(),
                           probe=None)


def _site_has_ldap() -> bool:
    try:
        with open(SITE_DEFAULT, encoding="utf-8") as f:
            t = f.read()
        return bool(re.search(r"^\tldap$", t, re.M)) and "Auth-Type LDAP {" in t
    except OSError:
        return False


@app.route("/ldap/save", methods=["POST"])
def ldap_save():
    values = {k: request.form.get(k, "").strip() for k in LDAP_FIELDS}
    save_ldap_conf(values)
    flash("LDAP 连接参数已保存（原文件已备份到 raddb/.backups/）。"
          "建议先「测试连接」再启用。", "ok")
    return redirect(url_for("ldap_page"))


@app.route("/ldap/test", methods=["POST"])
def ldap_test():
    d = load_ldap_conf()
    # 表单里带过来的临时值优先（方便改完直接测，不必先保存）
    for k in LDAP_FIELDS:
        v = request.form.get(k, "").strip()
        if v:
            d[k] = v
    probe = ldap_probe(d)
    compose = compose_read()
    return render_template("ldap.html", d=d,
                           enabled=ldap_compose_enabled(compose),
                           incomplete=ldap_conf_incomplete(d),
                           container=radius_container_status(),
                           site_ok=_site_has_ldap(),
                           probe=probe)


@app.route("/ldap/toggle", methods=["POST"])
def ldap_toggle():
    enable = request.form.get("action") == "enable"
    d = load_ldap_conf()
    compose = compose_read()
    if enable:
        bad = ldap_conf_incomplete(d)
        if bad:
            flash("无法启用：连接参数还不完整或仍是占位值（%s），请先填写保存并测试连通。"
                  % "、".join(bad), "error")
            return redirect(url_for("ldap_page"))
        if not _site_has_ldap():
            flash("无法启用：site-default 未包含 LDAP 认证配置，请检查文件。", "error")
            return redirect(url_for("ldap_page"))
    old = compose
    compose_write(compose_set_ldap(compose, enable))
    ok, out = compose_apply()
    if not ok:
        compose_write(old)
        compose_apply()
        flash("重建容器失败，已回滚。docker 输出：%s" % out, "error")
        return redirect(url_for("ldap_page"))
    if not compose_healthy():
        compose_write(old)
        compose_apply()
        st = radius_container_status()
        flash("启用后 RADIUS 启动异常（%s），已自动回滚恢复。最常见原因："
              "LDAP 服务器不可达或账号密码错误。" % st.get("detail", "?"), "error")
        return redirect(url_for("ldap_page"))
    if enable:
        flash("LDAP 模式已启用，RADIUS 运行正常。现在可以去「认证测试」页验证 "
              "LDAP 账号，并到配置文件页核对 users 里的组映射规则。", "ok")
    else:
        flash("LDAP 模式已停用，RADIUS 已恢复为本地 users 文件认证。", "ok")
    return redirect(url_for("ldap_page"))


# ---------------------------------------------------------------- 动态 VLAN
VLAN_MAP_FILE = os.path.join(RADDB, "vlan-map.json")
VLAN_BEGIN = "# === SHARKSSO-VLAN-BEGIN"
VLAN_END = "# === SHARKSSO-VLAN-END"
VLAN_MIN, VLAN_MAX = 1, 4094


def load_vlan_cfg() -> dict:
    try:
        with open(VLAN_MAP_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict):
            d = {}
    except (OSError, ValueError):
        d = {}
    d.setdefault("rules", [])
    d.setdefault("default_vlan", "")
    d.setdefault("updated_at", "")
    return d


def save_vlan_cfg(cfg: dict) -> None:
    _backup(VLAN_MAP_FILE)
    with open(VLAN_MAP_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def _vlan_ok(v) -> bool:
    s = str(v or "").strip()
    return s.isdigit() and VLAN_MIN <= int(s) <= VLAN_MAX


def ldap_departments() -> tuple:
    """从 LDAP 读部门组，返回 (列表, 错误信息)

    结构：ou=dingtalkroot 下的 groupOfUniqueNames，cn=部门拼音，
    description=中文名，uniqueMember=成员 DN 列表。
    """
    d = load_ldap_conf()
    base = (d.get("base_dn") or "").strip()
    gbase = (d.get("group_base_dn") or "").strip(",")
    if "${..base_dn}" in gbase:
        gbase = gbase.replace("${..base_dn}", base)
    gfilter = d.get("group_filter") or "(objectClass=groupOfUniqueNames)"
    if not d.get("server"):
        return [], "LDAP 连接参数未配置（缺少 server）"
    try:
        from ldap3 import Server, Connection, ALL
    except ImportError:
        return [], "容器内未安装 ldap3"
    try:
        srv = Server(d["server"], get_info=ALL, connect_timeout=6)
        conn = Connection(srv, user=d.get("identity") or None,
                          password=d.get("password") or None,
                          auto_bind=True, receive_timeout=15)
        conn.search(gbase, gfilter,
                    attributes=["cn", "description", "uniqueMember"],
                    size_limit=0)
        if conn.result.get("description") not in ("success", "success (0)"):
            return [], "组搜索失败：%s" % conn.result.get("description")
        out = []
        index = {}
        for entry in conn.response:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry.get("attributes") or {}
            cn = a.get("cn")
            cn = (cn[0] if isinstance(cn, list) else cn) or ""
            if not cn:
                continue
            cn = str(cn)
            desc = a.get("description")
            desc = (desc[0] if isinstance(desc, list) else desc) or ""
            mem = a.get("uniqueMember") or []
            if isinstance(mem, str):
                mem = [mem]
            # LDAP 里部门是嵌套树，同一部门可能在不同上级下各存一份，
            # RADIUS 只按 cn 匹配组名，所以这里按 cn 合并（成员取并集）
            if cn in index:
                it = index[cn]
                it["_dns"].add(entry.get("dn") or "")
                it["_mem"].update(str(m) for m in mem)
                if desc and not it["label"]:
                    it["label"] = str(desc)
                continue
            it = {"group": cn, "label": str(desc) or cn, "members": 0,
                  "_dns": {entry.get("dn") or ""},
                  "_mem": {str(m) for m in mem}}
            index[cn] = it
            out.append(it)
        for it in out:
            it["members"] = len([m for m in it["_mem"] if "uid=" in m])
            it["dups"] = len(it["_dns"])
            it.pop("_dns", None)
            it.pop("_mem", None)
        conn.unbind()
        out.sort(key=lambda x: (-x["members"], x["group"]))
        return out, ""
    except Exception as exc:
        return [], "连接 LDAP 失败：%s" % exc


def render_vlan_block(cfg: dict) -> str:
    """按配置生成 site-default 里的 unlang 片段（缩进用 tab）"""
    rules = [r for r in cfg.get("rules", [])
             if r.get("enabled") and _vlan_ok(r.get("vlan"))]
    dv = str(cfg.get("default_vlan") or "").strip()

    def tunnel(vlan, ind="\t\t"):
        return ["%supdate reply {" % ind,
                "%s\t&Tunnel-Type := VLAN" % ind,
                "%s\t&Tunnel-Medium-Type := IEEE-802" % ind,
                '%s\t&Tunnel-Private-Group-Id := "%s"' % (ind, vlan),
                "%s}" % ind]

    lines = ["\t" + VLAN_BEGIN +
             " （Web 面板「动态 VLAN」自动生成，手工改会被覆盖）"]
    lines.append("\t# 生效规则 %d 条 · 更新于 %s"
                 % (len(rules), cfg.get("updated_at") or "—"))
    lines.append("\t# 条件里的 !&reply:Tunnel-Private-Group-Id 保证两点："
                 "① users 文件里给单个用户指定的 VLAN 优先；"
                 "② 自上而下按顺序匹配，先命中先生效。")
    if not rules:
        lines.append("\t# 当前没有启用任何部门规则")
    for r in rules:
        label = r.get("label") or r.get("group")
        lines.append("\t# %s → VLAN %s" % (label, r["vlan"]))
        lines.append('\tif (&control:LDAP-Group == "%s" && !&reply:Tunnel-Private-Group-Id) {'
                     % r["group"])
        lines += tunnel(r["vlan"])
        lines.append("\t}")
    if _vlan_ok(dv):
        lines.append("\t# 兜底：LDAP 已认证、但没命中上面任何部门的账号 → VLAN %s" % dv)
        lines.append("\tif (&control:LDAP-Group && !&reply:Tunnel-Private-Group-Id) {")
        lines += tunnel(dv)
        lines.append("\t}")
    lines.append("\t" + VLAN_END)
    return "\n".join(lines)


def site_has_vlan_block() -> bool:
    try:
        with open(SITE_DEFAULT, encoding="utf-8") as f:
            return VLAN_BEGIN in f.read()
    except OSError:
        return False


def site_vlan_text() -> str:
    """取出 site-default 里已生成的块，供页面预览"""
    try:
        with open(SITE_DEFAULT, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    if VLAN_BEGIN not in text or VLAN_END not in text:
        return ""
    i = text.rindex("\n", 0, text.index(VLAN_BEGIN)) + 1
    j = text.index("\n", text.index(VLAN_END)) + 1
    return text[i:j]


def update_site_vlan(text: str, block: str) -> str:
    """把生成块写入 site-default：有 marker 就替换，没有就顶掉旧注释模板/插在 ldap 之后"""
    if VLAN_BEGIN in text and VLAN_END in text:
        i = text.rindex("\n", 0, text.index(VLAN_BEGIN)) + 1
        j = text.index("\n", text.index(VLAN_END)) + 1
        return text[:i] + block + "\n" + text[j:]
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("# ---- 部门 → 动态 VLAN"):
            j = i
            # 吃掉旧模板的整段注释（缩进注释 + 空行），遇到非注释行停
            while j < len(lines) and (not lines[j].strip()
                                      or lines[j].startswith("\t#")):
                j += 1
            lines[i:j] = block.splitlines() + [""]
            break
    else:
        for k, line in enumerate(lines):
            if line == "\tldap":
                lines[k + 1:k + 1] = [""] + block.splitlines() + [""]
                break
        else:
            return text  # 找不到插入点，原样返回
    return "\n".join(lines) + "\n"


def write_site_vlan(cfg: dict) -> tuple:
    """写入 site-default，返回 (ok, 说明)"""
    block = render_vlan_block(cfg)
    try:
        with open(SITE_DEFAULT, encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        return False, "读取 site-default 失败：%s" % exc
    new = update_site_vlan(text, block)
    if new == text:
        return False, "site-default 里找不到插入位置（缺少 ldap 行），未写入"
    _backup(SITE_DEFAULT)
    with open(SITE_DEFAULT, "w", encoding="utf-8") as f:
        f.write(new)
    return True, block


def radius_restart() -> tuple:
    try:
        p = subprocess.run(
            ["docker", "compose", "-f", RADIUS_COMPOSE, "restart", "radius"],
            capture_output=True, text=True, timeout=180)
        return p.returncode == 0, (p.stdout + p.stderr).strip()[-1500:]
    except Exception as exc:
        return False, str(exc)


def vlan_rows(cfg: dict, depts: list) -> list:
    """合并 LDAP 部门表与已存规则；LDAP 挂掉时用已存规则兜底"""
    by_group = {r.get("group"): r for r in cfg.get("rules", [])}
    rows, seen = [], set()
    for d in depts:
        r = by_group.get(d["group"], {})
        rows.append({
            "group": d["group"],
            "label": d.get("label") or r.get("label") or d["group"],
            "members": d.get("members", 0),
            "dups": d.get("dups", 1),
            "vlan": r.get("vlan", ""),
            "enabled": bool(r.get("enabled")),
            "stale": False,
        })
        seen.add(d["group"])
    for r in cfg.get("rules", []):
        g = r.get("group")
        if g and g not in seen:
            rows.append({
                "group": g,
                "label": r.get("label") or g,
                "members": None,
                "dups": 1,
                "vlan": r.get("vlan", ""),
                "enabled": bool(r.get("enabled")),
                "stale": True,   # LDAP 里已不存在（部门被删/改名）
            })
            seen.add(g)
    return rows


@app.route("/vlan", methods=["GET"])
def vlan_page():
    cfg = load_vlan_cfg()
    depts, err = ldap_departments()
    rows = vlan_rows(cfg, depts)
    summary = {}
    for r in rows:
        if r["enabled"] and str(r["vlan"]).isdigit():
            summary.setdefault(int(r["vlan"]), []).append(r["label"])
    return render_template("vlan.html", rows=rows, cfg=cfg, ldap_err=err,
                           applied=site_has_vlan_block(),
                           active_text=site_vlan_text(),
                           preview=render_vlan_block(cfg),
                           vlan_summary=sorted(summary.items()),
                           container=radius_container_status(),
                           ldap_enabled=ldap_compose_enabled(compose_read()))


@app.route("/vlan/save", methods=["POST"])
def vlan_save():
    action = request.form.get("action", "save")
    groups = request.form.getlist("g")
    labels = request.form.getlist("lbl")
    rules, bad, seen_g = [], [], set()
    for i, g in enumerate(groups):
        g = (g or "").strip()
        if not g or g in seen_g:
            continue
        seen_g.add(g)
        raw = request.form.get("vlan_%d" % i, "").strip()
        en = request.form.get("en_%d" % i) == "1"
        label = (labels[i] if i < len(labels) else g) or g
        if en:
            if not _vlan_ok(raw):
                bad.append("%s（VLAN 号「%s」无效，应为 %d-%d）"
                           % (label, raw, VLAN_MIN, VLAN_MAX))
                continue
            rules.append({"group": g, "label": label,
                          "vlan": int(raw), "enabled": True})
        else:
            rules.append({"group": g, "label": label,
                          "vlan": int(raw) if _vlan_ok(raw) else "",
                          "enabled": False})
    if bad:
        flash("未保存：以下部门的 VLAN 号不合法 —— " + "；".join(bad), "error")
        return redirect(url_for("vlan_page"))

    dv = request.form.get("default_vlan", "").strip()
    if dv and not _vlan_ok(dv):
        flash("未保存：兜底 VLAN「%s」不合法，应为 %d-%d 或留空" % (dv, VLAN_MIN, VLAN_MAX),
              "error")
        return redirect(url_for("vlan_page"))

    cfg = {"rules": rules, "default_vlan": dv if _vlan_ok(dv) else "",
           "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    save_vlan_cfg(cfg)
    ok, info = write_site_vlan(cfg)
    if not ok:
        flash("配置已存（vlan-map.json），但写入 site-default 失败：%s" % info, "error")
        return redirect(url_for("vlan_page"))

    on = sum(1 for r in rules if r["enabled"])
    if action != "apply":
        flash("已保存 %d 条规则（%d 条启用），site-default 已更新。"
              "点「保存并重启生效」让 RADIUS 加载。" % (len(rules), on), "ok")
        return redirect(url_for("vlan_page"))

    # 应用：重启 + 健康检查，异常自动回滚
    prev = site_vlan_text()
    ok2, out = radius_restart()
    if not ok2:
        flash("重启 RADIUS 失败，配置已保存但未生效。输出：%s" % out, "error")
        return redirect(url_for("vlan_page"))
    if not compose_healthy():
        st = radius_container_status()
        # 回滚到上一版块内容
        try:
            with open(SITE_DEFAULT, encoding="utf-8") as f:
                cur = f.read()
            back = update_site_vlan(cur, prev) if prev else update_site_vlan(
                cur, "\t" + VLAN_BEGIN + " （已回滚：本轮规则启动异常）\n\t" + VLAN_END)
            with open(SITE_DEFAULT, "w", encoding="utf-8") as f:
                f.write(back)
            radius_restart()
        except OSError:
            pass
        flash("重启后 RADIUS 启动异常（%s），已回滚上一版规则。"
              "常见原因：unlang 语法错（部门组名含特殊字符）或 LDAP 不可达。"
              % st.get("detail", "?"), "error")
        return redirect(url_for("vlan_page"))

    flash("已生效：%d 条启用规则 + 兜底 VLAN %s，RADIUS 运行正常。"
          "现在可以用「认证测试」验证某员工是否拿到预期 VLAN。"
          % (on, cfg["default_vlan"] or "未设"), "ok")
    return redirect(url_for("vlan_page"))


@app.route("/guide")
def guide_page():
    ac = next((c for c in load_clients() if c["name"] == "huawei-ac-4f-jf"), None)
    return render_template("guide.html",
                           ac_name=ac["name"] if ac else "huawei-ac-4f-jf",
                           ac_ip=ac["fields"].get("ipaddr", "172.16.1.253") if ac else "172.16.1.253",
                           ac_secret=ac["fields"].get("secret", "（未注册，去密钥管理页添加）") if ac else "（未注册，去密钥管理页添加）")


def _reload_hint() -> None:
    flash("配置已写入（原文件备份在 .backups/）。需在服务器执行 "
          "cd /opt/SharkSSO/radius && docker compose restart 后生效", "warn")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8082")))
