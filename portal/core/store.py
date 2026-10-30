"""SQLite 存储：在线会话 + 认证日志"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "portal.db")
_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT    NOT NULL UNIQUE,
    username     TEXT    NOT NULL,
    userip       TEXT    NOT NULL,
    mac          TEXT    DEFAULT '',
    ssid         TEXT    DEFAULT '',
    nasip        TEXT    DEFAULT '',
    started_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    ended_at     INTEGER DEFAULT 0,
    status       TEXT    NOT NULL DEFAULT 'online',
    release_info TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(userip, status);

CREATE TABLE IF NOT EXISTS logs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    userip   TEXT    DEFAULT '',
    username TEXT    DEFAULT '',
    action   TEXT    NOT NULL,
    result   TEXT    NOT NULL,
    detail   TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
"""


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, _conn() as conn:
        conn.executescript(SCHEMA)


def add_log(userip: str, username: str, action: str, result: str, detail: str = "") -> None:
    with _LOCK, _conn() as conn:
        conn.execute(
            "INSERT INTO logs (ts, userip, username, action, result, detail) "
            "VALUES (?,?,?,?,?,?)",
            (int(time.time()), userip, username, action, result, detail),
        )


def recent_logs(limit: int = 200, keyword: str = "") -> list[dict]:
    sql = "SELECT * FROM logs"
    args: list = []
    if keyword:
        sql += " WHERE username LIKE ? OR userip LIKE ?"
        args = [f"%{keyword}%", f"%{keyword}%"]
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as conn:
        return [dict(r) for r in conn.execute(sql, args)]


# ---------------------------------------------------------------- sessions
def open_session(username: str, userip: str, mac: str, ssid: str,
                 nasip: str, timeout: int) -> str:
    now = int(time.time())
    session_id = uuid.uuid4().hex[:16]
    with _LOCK, _conn() as conn:
        # 同一 IP 的旧会话直接置为 superseded，避免重复在线
        conn.execute(
            "UPDATE sessions SET status='superseded', ended_at=? "
            "WHERE userip=? AND status='online'", (now, userip))
        conn.execute(
            "INSERT INTO sessions (session_id, username, userip, mac, ssid, nasip,"
            " started_at, expires_at, status) VALUES (?,?,?,?,?,?,?,?,'online')",
            (session_id, username, userip, mac, ssid, nasip, now, now + timeout),
        )
    return session_id


def close_session(userip: str, reason: str = "logout") -> None:
    with _LOCK, _conn() as conn:
        conn.execute(
            "UPDATE sessions SET status=?, ended_at=? "
            "WHERE userip=? AND status='online'",
            (reason, int(time.time()), userip),
        )


def close_session_by_id(session_id: str, reason: str = "admin-kick") -> None:
    with _LOCK, _conn() as conn:
        conn.execute(
            "UPDATE sessions SET status=?, ended_at=? WHERE session_id=?",
            (reason, int(time.time()), session_id),
        )


def get_online_session(userip: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE userip=? AND status='online' "
            "ORDER BY started_at DESC LIMIT 1", (userip,)).fetchone()
        return dict(row) if row else None


def online_sessions(limit: int = 500) -> list[dict]:
    with _conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM sessions WHERE status='online' "
            "ORDER BY started_at DESC LIMIT ?", (limit,))]


def expired_sessions() -> list[dict]:
    with _conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM sessions WHERE status='online' AND expires_at < ?",
            (int(time.time()),))]


def stats() -> dict:
    with _conn() as conn:
        online = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE status='online'").fetchone()[0]
        today_start = int(time.time()) - 86400
        auth_ok = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE action='AUTH' AND result='OK' AND ts>?",
            (today_start,)).fetchone()[0]
        auth_fail = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE action='AUTH' AND result='FAIL' AND ts>?",
            (today_start,)).fetchone()[0]
    return {"online": online, "auth_ok": auth_ok, "auth_fail": auth_fail}
