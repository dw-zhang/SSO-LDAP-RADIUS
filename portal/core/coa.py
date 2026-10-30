"""RFC 5176 CoA / Disconnect 客户端

用途：
  authorize()  —— 认证通过后给 AC 下发授权（限速、ACL），或作为 Portal 协议的兜底放行
  disconnect() —— 管理后台手动踢用户下线

说明：AC 是否接受对「尚未通过 RADIUS 认证的会话」下发 CoA，取决于设备版本与
配置。若 CoA 返回 NAK，请以 Portal 协议的 AFF_ACK_AUTH 为主通道。
"""

from __future__ import annotations

import logging
import os

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

log = logging.getLogger("portal.coa")

DICT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dictionary")

CODE_NAME = {
    pyrad.packet.CoAACK: "CoA-ACK",
    pyrad.packet.CoANAK: "CoA-NAK",
    pyrad.packet.DisconnectACK: "Disconnect-ACK",
    pyrad.packet.DisconnectNAK: "Disconnect-NAK",
}


class CoAClient:
    def __init__(self, nas_ip: str, secret: str, port: int = 3799, timeout: int = 3):
        self.nas_ip = nas_ip
        self.secret = secret
        self.port = port
        self.timeout = timeout
        self._dict = Dictionary(DICT_PATH)

    def _client(self) -> Client:
        return Client(
            server=self.nas_ip,
            coaport=self.port,
            secret=self.secret.encode(),
            dict=self._dict,
            timeout=self.timeout,
            retries=1,
        )

    # ------------------------------------------------------------------
    def authorize(self, userip: str, attrs: dict | None = None) -> tuple[bool, str]:
        """下发授权属性。

        只要 attrs 里带 Tunnel-Private-Group-Id，就自动补齐
        Tunnel-Type=VLAN(13) 与 Tunnel-Medium-Type=IEEE-802(6) ——
        AC 三个属性缺一不可，否则收到也不会切 VLAN。
        """
        attrs = dict(attrs or {})
        payload = {"Framed_IP_Address": userip}

        vlan = attrs.get("Tunnel-Private-Group-Id")
        if isinstance(vlan, list):
            vlan = vlan[0] if vlan else None
        if vlan not in (None, ""):
            payload["Tunnel_Type"] = 13
            payload["Tunnel_Medium_Type"] = 6
            payload["Tunnel_Private_Group_Id"] = str(vlan)

        mapping = {
            "Filter-Id": "Filter_Id",
            "Session-Timeout": "Session_Timeout",
            "Idle-Timeout": "Idle_Timeout",
        }
        for src, dst in mapping.items():
            if src in attrs:
                payload[dst] = attrs[src]

        client = self._client()
        try:
            req = client.CreateCoAPacket(code=pyrad.packet.CoARequest, **payload)
        except Exception as exc:
            log.warning("构造 CoA 报文失败: %s", exc)
            return False, f"构造报文失败: {exc}"

        try:
            reply = client.SendPacket(req)
        except Exception as exc:
            log.warning("CoA 发送失败 %s:%d -> %s", self.nas_ip, self.port, exc)
            return False, f"CoA 不可达: {exc}"

        name = CODE_NAME.get(reply.code, str(reply.code))
        if reply.code == pyrad.packet.CoAACK:
            log.info("CoA 授权成功 userip=%s attrs=%s", userip, payload)
            return True, name
        cause = reply.get("Error-Cause", [""])
        log.info("CoA 被拒绝 userip=%s code=%s cause=%s", userip, name, cause)
        return False, f"{name} {cause}"

    # ------------------------------------------------------------------
    def disconnect(self, userip: str) -> tuple[bool, str]:
        """强制用户下线"""
        client = self._client()
        try:
            req = client.CreateCoAPacket(code=pyrad.packet.DisconnectRequest,
                                         Framed_IP_Address=userip)
        except Exception as exc:
            return False, f"构造报文失败: {exc}"

        try:
            reply = client.SendPacket(req)
        except Exception as exc:
            log.warning("Disconnect 发送失败 %s -> %s", userip, exc)
            return False, f"不可达: {exc}"

        name = CODE_NAME.get(reply.code, str(reply.code))
        ok = reply.code == pyrad.packet.DisconnectACK
        log.info("踢下线 userip=%s 结果=%s", userip, name)
        return ok, name
