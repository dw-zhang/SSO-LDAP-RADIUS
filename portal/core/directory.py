"""LDAP 目录查询：钉钉身份 -> 员工账号 -> 所属部门

LDAP 在这里只当「属性库」用（人名、部门、组），不参与密码校验。
Portal 拿到钉钉核验过的手机号后，靠手机号在 LDAP 里认人，
再反查他所在的部门组，交给 RADIUS 决定 VLAN。
"""

from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger("portal.directory")


def _escape(value: str) -> str:
    try:
        from ldap3.utils.conv import escape_filter_chars
        return escape_filter_chars(str(value))
    except Exception:
        return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class DirectoryError(Exception):
    pass


class Directory:
    def __init__(self, uri: str, bind_dn: str, bind_pw: str,
                 people_base: str, group_base: str,
                 timeout: int = 5, cache_ttl: int = 300):
        self.uri = uri
        self.bind_dn = bind_dn
        self.bind_pw = bind_pw
        self.people_base = people_base
        self.group_base = group_base
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: dict = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- 连接
    def _conn(self):
        try:
            from ldap3 import Server, Connection
        except ImportError:
            raise DirectoryError("服务端缺少 ldap3 库")
        srv = Server(self.uri, connect_timeout=self.timeout)
        try:
            return Connection(srv, user=self.bind_dn, password=self.bind_pw,
                              auto_bind=True, receive_timeout=self.timeout)
        except Exception as exc:
            raise DirectoryError("无法连接 LDAP（%s）：%s" % (self.uri, exc))

    # ---------------------------------------------------------------- 认人
    def find_person(self, mobile: str = "", email: str = "", name: str = "") -> dict | None:
        """按 手机号 > 邮箱 > 姓名 的顺序匹配，返回员工条目（含所属部门）"""
        parts = []
        if mobile:
            parts.append("(mobile=%s)" % _escape(mobile))
        if email:
            parts.append("(mail=%s)" % _escape(email))
        if name:
            parts.append("(cn=%s)" % _escape(name))
        if not parts:
            return None

        key = "|".join(filter(None, [mobile, email, name]))
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.time() < hit[0]:
                return hit[1]

        flt = "(&(objectClass=inetOrgPerson)(|%s))" % "".join(parts)
        conn = self._conn()
        try:
            conn.search(self.people_base, flt,
                        attributes=["uid", "cn", "mail", "mobile"],
                        size_limit=5)
            rows = [e for e in conn.response if e.get("type") == "searchResEntry"]
            if not rows:
                with self._lock:
                    self._cache[key] = (time.time() + 60, None)
                return None

            def pick(entry):
                a = entry.get("attributes") or {}
                one = lambda k: (a.get(k)[0] if isinstance(a.get(k), list)
                                 else a.get(k)) or ""
                return {"uid": str(one("uid")), "name": str(one("cn")),
                        "mail": str(one("mail")), "mobile": str(one("mobile")),
                        "dn": entry.get("dn", "")}

            person = pick(rows[0])
            # 手机号匹配到多人属于数据问题，明确报错而不是随便挑一个
            if mobile and len(rows) > 1:
                same = [p for p in (pick(r) for r in rows) if p["mobile"] == mobile]
                if len(same) > 1:
                    raise DirectoryError("手机号 %s 在通讯录里对应多条记录：%s"
                                         % (mobile, "、".join(p["uid"] for p in same)))
            person["groups"], person["labels"] = self._groups_of(conn, person["dn"])
            with self._lock:
                self._cache[key] = (time.time() + self.cache_ttl, person)
            return person
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    # ---------------------------------------------------------------- 部门
    def _groups_of(self, conn, person_dn: str) -> tuple[list, dict]:
        """返回 (部门 cn 列表, {cn: 中文名})，按成员数多的排前面（大部门优先）"""
        if not person_dn:
            return [], {}
        flt = "(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" % _escape(person_dn)
        conn.search(self.group_base, flt, attributes=["cn", "description"],
                    size_limit=0)
        groups, labels, seen = [], {}, set()
        for entry in conn.response:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry.get("attributes") or {}
            cn = a.get("cn")
            cn = (cn[0] if isinstance(cn, list) else cn) or ""
            if not cn or cn in seen:
                continue
            desc = a.get("description")
            desc = (desc[0] if isinstance(desc, list) else desc) or ""
            seen.add(str(cn))
            groups.append(str(cn))
            labels[str(cn)] = str(desc)
        return groups, labels

    # ---------------------------------------------------------------- 健康检查
    def ping(self) -> tuple[bool, str]:
        try:
            conn = self._conn()
            conn.unbind()
            return True, "LDAP 连接正常"
        except Exception as exc:
            return False, str(exc)
