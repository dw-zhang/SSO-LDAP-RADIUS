"""端到端自检：不需要真实 AC 和 RADIUS，验证 Portal 服务器全链路

用法（先启动 app.py，再另开终端跑）：
    python tools/selftest.py

它会临时扮演三个角色：
    1. 假 RADIUS 服务器（1812）—— 回 Access-Accept
    2. 假 CoA 服务端（3799）—— 回 CoA-ACK / Disconnect-ACK
    3. 假 AC（随机端口）—— 向 Portal 发 REQ_AUTH，并等待 AFF_ACK_AUTH

全部通过说明：协议编解码、RADIUS 认证、放行通知、Web 登录链路都正常。
建议在正式接 AC 之前先跑一遍，把问题挡在本地。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import portal_proto as pp  # noqa: E402

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
COA_REQUEST, COA_ACK = 43, 44
DISCONNECT_REQUEST, DISCONNECT_ACK = 40, 41


def parse_radius(data: bytes):
    code, ident, length = struct.unpack("!BBH", data[:4])
    authenticator = data[4:20]
    body = data[20:length]
    attrs, i = {}, 0
    while i + 2 <= len(body):
        t, ln = body[i], body[i + 1]
        if ln < 2:
            break
        attrs[t] = body[i + 2:i + ln]
        i += ln
    return code, ident, authenticator, attrs


def build_reply(code: int, ident: int, req_auth: bytes,
                attrs: bytes, secret: bytes) -> bytes:
    length = 20 + len(attrs)
    head = struct.pack("!BBH", code, ident, length) + req_auth
    return struct.pack("!BBH", code, ident, length) + \
        hashlib.md5(head + attrs + secret).digest() + attrs


class FakeRadius(threading.Thread):
    daemon = True

    def __init__(self, port: int, secret: str):
        super().__init__(name="fake-radius")
        self.port, self.secret = port, secret.encode()
        self.seen: list[str] = []

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        while True:
            data, peer = sock.recvfrom(4096)
            code, ident, auth, attrs = parse_radius(data)
            user = attrs.get(1, b"").decode(errors="ignore")
            self.seen.append(f"{code}:{user}")
            if user == "baduser":
                reply = build_reply(ACCESS_REJECT, ident, auth, b"", self.secret)
            else:
                reply = build_reply(ACCESS_ACCEPT, ident, auth, b"", self.secret)
            sock.sendto(reply, peer)


class FakeCoA(threading.Thread):
    daemon = True

    def __init__(self, port: int, secret: str):
        super().__init__(name="fake-coa")
        self.port, self.secret = port, secret.encode()
        self.seen: list[int] = []

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        while True:
            data, peer = sock.recvfrom(4096)
            code, ident, auth, _ = parse_radius(data)
            self.seen.append(code)
            ack = COA_ACK if code == COA_REQUEST else DISCONNECT_ACK
            sock.sendto(build_reply(ack, ident, auth, b"", self.secret), peer)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8081")
    ap.add_argument("--radius-port", type=int, default=1812)
    ap.add_argument("--coa-port", type=int, default=3799)
    ap.add_argument("--portal-port", type=int, default=50101)
    ap.add_argument("--secret", default="k2")
    ap.add_argument("--coa-secret", default="k3")
    ap.add_argument("--userip", default="10.10.28.88")
    args = ap.parse_args()

    print("1) 启动假 RADIUS / CoA ...")
    fr = FakeRadius(args.radius_port, args.secret)
    fc = FakeCoA(args.coa_port, args.coa_secret)
    fr.start()
    fc.start()
    time.sleep(0.3)

    print("2) 扮演 AC，向 Portal 发 REQ_AUTH ...")
    ac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ac.settimeout(5)
    ac.bind(("127.0.0.1", 0))
    ac_addr = ac.getsockname()
    req = pp.build_packet(pp.REQ_AUTH, args.userip, serialno=4321, reqid=1, seqno=1)
    ac.sendto(req, ("127.0.0.1", args.portal_port))
    try:
        ack, _ = ac.recvfrom(4096)
        print(f"   <- ACK 长度 {len(ack)} 字节")
    except socket.timeout:
        print("   [FAIL] AC 没收到 ACK_AUTH，检查 Portal UDP 端口与监听地址")
        sys.exit(1)

    print("3) 提交登录表单 ...")
    form = urllib.parse.urlencode({
        "userip": args.userip, "username": "selftest",
        "password": "good", "ssid": "Corp-Guest", "mac": "",
    }).encode()
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(args.url + "/login", data=form), timeout=10)
        html = r.read().decode("utf-8", "ignore")
    except Exception as exc:
        print(f"   [FAIL] 请求登录页失败: {exc}")
        sys.exit(1)

    ok_page = "连接成功" in html
    print(f"   页面结果: {'连接成功' if ok_page else '未显示成功'}")

    print("4) 等待 AC 收到 AFF_ACK_AUTH ...")
    got_aff = False
    try:
        while True:
            data, _ = ac.recvfrom(4096)
            pkt = pp.PortalPacket(data)
            print(f"   <- {pkt.describe()}")
            if pkt.type == pp.AFF_ACK_AUTH:
                got_aff = True
                break
    except socket.timeout:
        pass

    print("5) 汇总")
    result = {
        "RADIUS 收到认证请求": bool(fr.seen),
        "CoA 收到授权请求": COA_REQUEST in fc.seen,
        "Web 页面显示成功": ok_page,
        "AC 收到 AFF_ACK_AUTH": got_aff,
    }
    for k, v in result.items():
        print(f"   {'PASS' if v else 'FAIL'}  {k}")

    if all(result.values()):
        print("\n全部通过：Portal 服务器与 RADIUS、AC 的交互链路正常。")
        sys.exit(0)

    print("\n有失败项，按下面顺序排查：")
    if not result["RADIUS 收到认证请求"]:
        print("  - 检查 config.yaml 的 radius.host / auth_port / secret 是否与 FreeRADIUS 一致")
        print("  - 在服务器上: tcpdump -i any -nn port 1812")
    if not result["CoA 收到授权请求"]:
        print("  - release_mode 是否为 coa/both；检查 ac.coa_secret 与 AC 的 radius-server authorization 配置")
    if not result["AC 收到 AFF_ACK_AUTH"]:
        print("  - 检查 Portal UDP 端口是否放通、SerialNo 是否为 0")
    sys.exit(1)


if __name__ == "__main__":
    main()
