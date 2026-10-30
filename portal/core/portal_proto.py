"""
华为 Portal 协议 v2 报文编解码 + UDP 服务端

报文结构（16 字节头 + N 个属性 TLV）：
    Ver(1) Type(1) SeqNo(2) ReqID(2) UserIP(4) UserPort(2)
    ErrCode(1) AttrNum(1) SerialNo(2)
    └─ 属性：AttrType(1) AttrLen(1) AttrValue(Len-2)

重要说明
--------
1. 该实现依据华为 Portal 协议 v2 公开规范编写，报文头字段是稳定的。
2. 不同 AC 版本在「属性个数 / 属性长度是否含头部 / 用户名密码携带方式」
   上存在差异。首次联调请把 config.yaml 的 log_level 设为 DEBUG，
   本模块会把每条报文的原始十六进制完整打印，用于对照校准。
3. 认证放行最关键的一个报文是 AFF_ACK_AUTH，只要它被 AC 正确接收，
   终端就会被放行，因此务必核对 SerialNo 是否与 AC 下发的一致。
"""

from __future__ import annotations

import binascii
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

log = logging.getLogger("portal.proto")

# ---------------------------- 报文类型 ----------------------------
REQ_CHALLENGE = 0x01
ACK_CHALLENGE = 0x02
REQ_AUTH = 0x03
ACK_AUTH = 0x04
REQ_LOGOUT = 0x05
ACK_LOGOUT = 0x06
AFF_ACK_AUTH = 0x07
NTF_LOGOUT = 0x08
REQ_INFO = 0x09
ACK_INFO = 0x0A
NTF_USERIP_CHANGE = 0x0B
ACK_USERIP_CHANGE = 0x0C

TYPE_NAME = {
    REQ_CHALLENGE: "REQ_CHALLENGE",
    ACK_CHALLENGE: "ACK_CHALLENGE",
    REQ_AUTH: "REQ_AUTH",
    ACK_AUTH: "ACK_AUTH",
    REQ_LOGOUT: "REQ_LOGOUT",
    ACK_LOGOUT: "ACK_LOGOUT",
    AFF_ACK_AUTH: "AFF_ACK_AUTH",
    NTF_LOGOUT: "NTF_LOGOUT",
    REQ_INFO: "REQ_INFO",
    ACK_INFO: "ACK_INFO",
    NTF_USERIP_CHANGE: "NTF_USERIP_CHANGE",
    ACK_USERIP_CHANGE: "ACK_USERIP_CHANGE",
}

# ---------------------------- 属性类型 ----------------------------
ATTR_USERIP = 0x01
ATTR_USERPORT = 0x02
ATTR_SERIALNO = 0x03
ATTR_SESSIONID = 0x04
ATTR_TEXTINFO = 0x05
ATTR_BASIP = 0x06
ATTR_USERIPV6 = 0x07
ATTR_USERMAC = 0x08

ATTR_NAME = {
    ATTR_USERIP: "UserIP",
    ATTR_USERPORT: "UserPort",
    ATTR_SERIALNO: "SerialNo",
    ATTR_SESSIONID: "SessionID",
    ATTR_TEXTINFO: "TextInfo",
    ATTR_BASIP: "BASIP",
    ATTR_USERIPV6: "UserIPv6",
    ATTR_USERMAC: "UserMAC",
}

HEADER = struct.Struct("!BBHH4sHBBH")
HEADER_LEN = HEADER.size  # 16

# 属性长度字段是否包含 AttrType+AttrLen 两个字节
# 华为规范中 AttrLen 为整个 TLV 长度；若你的 AC 版本按裸值长度处理，改成 False
ATTR_LEN_INCLUDES_HEADER = True


@dataclass
class PendingAuth:
    """AC 曾主动通知过的待认证会话，供 Web 登录时取 SerialNo 使用"""
    userip: str
    serialno: int = 0
    reqid: int = 0
    seqno: int = 0
    basip: str = ""
    username: str = ""
    peer: tuple = ()
    updated_at: float = field(default_factory=time.time)


def _decode_text(value: bytes) -> str:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return value.decode(enc).strip("\x00").strip()
        except UnicodeDecodeError:
            continue
    return repr(value)


class PortalPacket:
    def __init__(self, data: bytes):
        if len(data) < HEADER_LEN:
            raise ValueError(f"报文过短: {len(data)} 字节")
        self.raw = data
        (
            self.ver,
            self.type,
            self.seqno,
            self.reqid,
            ip_raw,
            self.userport,
            self.errcode,
            self.attrnum,
            self.serialno,
        ) = HEADER.unpack_from(data, 0)
        self.userip = socket.inet_ntoa(ip_raw)
        self.attrs: dict[int, bytes] = {}
        self._parse_attrs(data[HEADER_LEN:])

    def _parse_attrs(self, body: bytes) -> None:
        offset = 0
        while offset + 2 <= len(body):
            attr_type = body[offset]
            attr_len = body[offset + 1]
            if ATTR_LEN_INCLUDES_HEADER:
                value_len = attr_len - 2
            else:
                value_len = attr_len
            if value_len < 0 or offset + 2 + value_len > len(body):
                log.warning("属性解析越界 type=0x%02x len=%d 剩余=%d",
                            attr_type, attr_len, len(body) - offset)
                break
            self.attrs[attr_type] = body[offset + 2: offset + 2 + value_len]
            offset += 2 + value_len

    @property
    def type_name(self) -> str:
        return TYPE_NAME.get(self.type, f"0x{self.type:02x}")

    @property
    def text(self) -> str:
        return _decode_text(self.attrs.get(ATTR_TEXTINFO, b""))

    def hexdump(self) -> str:
        return binascii.hexlify(self.raw, " ").decode()

    def describe(self) -> str:
        attr_desc = ", ".join(
            f"{ATTR_NAME.get(k, hex(k))}={v!r}" for k, v in self.attrs.items()
        )
        return (
            f"v{self.ver} {self.type_name} seq={self.seqno} req={self.reqid} "
            f"userip={self.userip} port={self.userport} err={self.errcode} "
            f"attrnum={self.attrnum} serial={self.serialno} attrs=[{attr_desc}]"
        )


def build_packet(ptype: int, userip: str, serialno: int = 0, reqid: int = 0,
                 seqno: int = 0, errcode: int = 0,
                 attrs: dict[int, bytes] | None = None) -> bytes:
    attrs = attrs or {}
    body = bytearray()
    for attr_type, value in attrs.items():
        attr_len = len(value) + 2 if ATTR_LEN_INCLUDES_HEADER else len(value)
        body += struct.pack("!BB", attr_type, attr_len) + value
    return HEADER.pack(
        2, ptype, seqno, reqid, socket.inet_aton(userip),
        0, errcode, len(attrs), serialno,
    ) + bytes(body)


class PortalServer(threading.Thread):
    """监听 UDP 50100，接收 AC 主动下发的 Portal 报文"""

    daemon = True

    def __init__(self, bind_ip: str, bind_port: int,
                 on_logout=None, pending: dict[str, PendingAuth] | None = None):
        super().__init__(name="portal-udp")
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.on_logout = on_logout
        self.pending: dict[str, PendingAuth] = pending if pending is not None else {}
        self._stop_event = threading.Event()
        self.sock: socket.socket | None = None

    def stop(self) -> None:
        self._stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def run(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_ip, self.bind_port))
        log.info("Portal 协议监听 udp://%s:%d", self.bind_ip, self.bind_port)
        while not self._stop_event.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                break
            try:
                self._dispatch(data, peer)
            except Exception:
                log.exception("处理 Portal 报文异常，原始数据: %s",
                              binascii.hexlify(data, " ").decode())

    # ------------------------------------------------------------
    def _dispatch(self, data: bytes, peer: tuple) -> None:
        pkt = PortalPacket(data)
        log.debug("收包 <- %s:%d %s", peer[0], peer[1], pkt.describe())
        log.debug("原始报文: %s", pkt.hexdump())

        if pkt.type == REQ_CHALLENGE:
            self._save_pending(pkt, peer)
            self._reply(pkt, ACK_CHALLENGE, peer, errcode=0)

        elif pkt.type == REQ_AUTH:
            self._save_pending(pkt, peer)
            self._reply(pkt, ACK_AUTH, peer, errcode=0)

        elif pkt.type == REQ_LOGOUT:
            self._save_pending(pkt, peer)
            self._reply(pkt, ACK_LOGOUT, peer, errcode=0)
            log.info("AC 请求下线 userip=%s", pkt.userip)
            if self.on_logout:
                self.on_logout(pkt.userip, "AC-REQ-LOGOUT")

        elif pkt.type == NTF_LOGOUT:
            log.info("AC 通知用户已掉线 userip=%s", pkt.userip)
            if self.on_logout:
                self.on_logout(pkt.userip, "AC-NTF-LOGOUT")

        elif pkt.type == NTF_USERIP_CHANGE:
            self._reply(pkt, ACK_USERIP_CHANGE, peer, errcode=0)

        else:
            log.debug("忽略未知报文类型 %s", pkt.type_name)

    def _save_pending(self, pkt: PortalPacket, peer: tuple) -> None:
        basip = pkt.attrs.get(ATTR_BASIP, b"")
        item = PendingAuth(
            userip=pkt.userip,
            serialno=pkt.serialno,
            reqid=pkt.reqid,
            seqno=pkt.seqno,
            basip=socket.inet_ntoa(basip) if len(basip) == 4 else "",
            username=pkt.text,
            peer=peer,
        )
        self.pending[pkt.userip] = item
        log.info("登记待认证会话 userip=%s serial=%d reqid=%d user=%s",
                 item.userip, item.serialno, item.reqid, item.username or "-")

    def _reply(self, pkt: PortalPacket, rtype: int, peer: tuple, errcode: int = 0) -> None:
        data = build_packet(rtype, pkt.userip, serialno=pkt.serialno,
                            reqid=pkt.reqid, seqno=pkt.seqno, errcode=errcode)
        self.sock.sendto(data, peer)
        log.debug("回包 -> %s:%d type=%s", peer[0], peer[1],
                  TYPE_NAME.get(rtype, hex(rtype)))

    # ------------------------------------------------------------
    def aff_ack_auth(self, userip: str, peer: tuple | None = None,
                     timeout: int = 5) -> bool:
        """认证成功后通知 AC 放行。返回 True 表示报文已发出（UDP 无确认）"""
        item = self.pending.get(userip)
        if not item:
            log.warning("未找到 %s 的待认证会话，无法发送 AFF_ACK_AUTH。"
                        "请确认 AC 侧是二层 Portal（会主动发 REQ_CHALLENGE/REQ_AUTH）",
                        userip)
            return False
        if item.serialno == 0:
            log.warning("%s 的 SerialNo 为 0，AC 可能拒绝该放行报文", userip)
        target = peer or item.peer
        if not target:
            log.warning("缺少 AC 地址，无法发送 AFF_ACK_AUTH")
            return False

        data = build_packet(AFF_ACK_AUTH, userip, serialno=item.serialno,
                            reqid=item.reqid, seqno=item.seqno)
        assert self.sock is not None
        for _ in range(3):
            self.sock.sendto(data, target)
            time.sleep(0.05)
        log.info("已发送 AFF_ACK_AUTH -> %s:%d userip=%s serial=%d",
                 target[0], target[1], userip, item.serialno)
        return True
