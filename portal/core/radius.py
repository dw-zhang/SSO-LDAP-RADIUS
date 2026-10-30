"""RADIUS 客户端封装（认证 + 计费）"""

from __future__ import annotations

import logging
import os

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

log = logging.getLogger("portal.radius")

DICT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dictionary")


class RadiusAuth:
    def __init__(self, host: str, secret: str, nas_ip: str,
                 auth_port: int = 1812, acct_port: int = 1813,
                 timeout: int = 3, retries: int = 2):
        self.host = host
        self.secret = secret
        self.nas_ip = nas_ip
        self.auth_port = auth_port
        self.acct_port = acct_port
        self.timeout = timeout
        self.retries = retries
        self._dict = Dictionary(DICT_PATH)

    def _client(self, port: int) -> Client:
        return Client(
            server=self.host,
            authport=port,
            acctport=port,
            secret=self.secret.encode(),
            dict=self._dict,
            timeout=self.timeout,
            retries=self.retries,
        )

    # ------------------------------------------------------------------
    def authenticate(self, username: str, password: str, userip: str,
                     ssid: str = "", mac: str = "") -> tuple[bool, str, dict]:
        """PAP 认证。返回 (是否通过, 提示信息, 命中的授权属性)"""
        client = self._client(self.auth_port)
        try:
            req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                          User_Name=username)
        except Exception as exc:  # 字典或参数问题
            log.exception("构造 RADIUS 报文失败")
            return False, f"内部错误: {exc}", {}

        try:
            req["User-Password"] = req.PwCrypt(password)
        except Exception as exc:
            log.exception("密码加密失败（检查 RADIUS secret）")
            return False, f"密码加密失败: {exc}", {}

        req["NAS-IP-Address"] = self.nas_ip
        req["NAS-Port"] = 0
        req["NAS-Port-Type"] = 19  # Wireless-IEEE-802.11
        req["Service-Type"] = 1    # Login-User
        req["NAS-Identifier"] = "portal-server"
        if ssid:
            req["Called-Station-Id"] = ssid
        if mac:
            req["Calling-Station-Id"] = mac
        if userip:
            try:
                req["Framed-IP-Address"] = userip
            except Exception:
                pass

        try:
            reply = client.SendPacket(req)
        except Exception as exc:
            log.warning("RADIUS 通信失败 %s:%d -> %s", self.host, self.auth_port, exc)
            return False, f"RADIUS 服务器不可达（{self.host}:{self.auth_port}）", {}

        granted = {}
        for key, values in reply.items():
            try:
                granted[key] = values[0] if len(values) == 1 else list(values)
            except Exception:
                granted[key] = repr(values)

        if reply.code == pyrad.packet.AccessAccept:
            log.info("认证通过 user=%s ip=%s", username, userip)
            return True, "认证成功", granted
        if reply.code == pyrad.packet.AccessReject:
            reason = reply.get("Reply-Message", ["用户名或密码错误"])
            msg = reason[0] if isinstance(reason, list) and reason else str(reason)
            log.info("认证拒绝 user=%s ip=%s msg=%s", username, userip, msg)
            return False, msg, granted

        log.warning("RADIUS 返回未知码 %s user=%s", reply.code, username)
        return False, f"RADIUS 返回异常码 {reply.code}", granted

    # ------------------------------------------------------------------
    def accounting(self, username: str, userip: str, session_id: str,
                   status: int, ssid: str = "", mac: str = "",
                   session_time: int = 0) -> None:
        """发计费报文（Start=1 / Stop=2），失败不影响认证主流程"""
        client = self._client(self.acct_port)
        try:
            req = client.CreateAcctPacket(User_Name=username)
            req["Acct-Status-Type"] = status
            req["Acct-Session-Id"] = session_id
            req["NAS-IP-Address"] = self.nas_ip
            req["Service-Type"] = 1
            req["NAS-Port-Type"] = 19
            if session_time:
                req["Acct-Session-Time"] = session_time
            if ssid:
                req["Called-Station-Id"] = ssid
            if mac:
                req["Calling-Station-Id"] = mac
            if userip:
                req["Framed-IP-Address"] = userip
            client.SendPacket(req)
        except Exception as exc:
            log.debug("计费报文发送失败（可忽略）: %s", exc)
