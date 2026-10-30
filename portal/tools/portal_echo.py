"""Portal 报文抓取与解析工具（协议校准用）

用法：
    python tools/portal_echo.py --port 50100

作用：在 50100 端口监听 AC 发来的 Portal 报文，把原始十六进制和解析结果
全部打印出来。第一次和 AC 联调时先跑这个，再对照 core/portal_proto.py
里的字段定义确认是否一致。

1. 先停掉 app.py（端口会被占用）
2. 运行本脚本
3. 让一台终端连 SSID，观察是否收到 REQ_CHALLENGE / REQ_AUTH
4. 收到后按 Ctrl+C，把输出发给开发/我，即可确认协议版本与字段
"""

from __future__ import annotations

import argparse
import binascii
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.portal_proto import PortalPacket  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=50100)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.ip, args.port))
    print(f"监听 udp://{args.ip}:{args.port}，等待 AC 报文（Ctrl+C 退出）\n")

    count = 0
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except KeyboardInterrupt:
            print(f"\n退出，共收到 {count} 条报文")
            break
        count += 1
        print("=" * 72)
        print(f"#{count} 来自 {peer[0]}:{peer[1]}  长度 {len(data)} 字节")
        print(f"原始: {binascii.hexlify(data, ' ').decode()}")
        try:
            pkt = PortalPacket(data)
            print(f"解析: {pkt.describe()}")
        except Exception as exc:
            print(f"解析失败: {exc}")
            print("（说明字段布局与 core/portal_proto.py 不一致，需要按原始报文校准）")
        print()


if __name__ == "__main__":
    main()
