#!/usr/bin/env python3
"""Host-side capture + ARP reply echo for the Aegis e1000 demo.

QEMU is launched with `-nic socket,connect=127.0.0.1:PORT,model=e1000e,...`
(an external helper, like this script, accepts the connection).
Each packet on the socket netdev is framed as: uint32 big-endian length,
then the raw Ethernet frame bytes (net/socket.c `net_socket_receive`).

This process:
  1. listens on 127.0.0.1:PORT and accepts QEMU's connection,
  2. reads every frame, writes it to a pcap (link type 1, Ethernet),
  3. for the first broadcast ARP request (op 1) it echoes an ARP reply
     back into the guest from gateway 10.0.2.2, so the kernel's polled
     RX ring has a real external packet to receive.

Usage: python e1000_host_listener.py PORT OUTFILE.pcap
"""

import socket
import struct
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: e1000_host_listener.py PORT OUTFILE.pcap", file=sys.stderr)
        return 2

    port = int(sys.argv[1])
    outfile = sys.argv[2]

    # ---- pcap global header: magic, version 2.4, thiszone, sigfigs,
    # snaplen 65535, network = 1 (Ethernet) ----
    pcap = open(outfile, "wb")
    pcap.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    pcap.flush()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    print(f"listener: waiting for QEMU on 127.0.0.1:{port} ...", flush=True)
    conn, addr = sock.accept()
    print(f"listener: QEMU connected from {addr}", flush=True)
    conn.settimeout(30.0)

    buf = bytearray()
    echoed = False
    total = 0
    while True:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            print("listener: timeout waiting for frames", flush=True)
            break
        if not chunk:
            print("listener: QEMU closed the connection", flush=True)
            break
        buf.extend(chunk)

        while len(buf) >= 4:
            (flen,) = struct.unpack(">I", bytes(buf[:4]))
            if len(buf) < 4 + flen:
                break
            frame = bytes(buf[4 : 4 + flen])
            del buf[: 4 + flen]
            total += 1

            # Record the frame in the pcap, flushing each time so the pcap
            # is usable even if this process is killed mid-run.
            ts = struct.pack("<II", 0, 0)
            pcap.write(ts)
            pcap.write(struct.pack("<II", len(frame), len(frame)))
            pcap.write(frame)
            pcap.flush()

            proto = frame[12:14]
            if proto == b"\x08\x06" and len(frame) >= 42:
                op = frame[20:22]
                if op == b"\x00\x01":
                    sender_mac = frame[6:12]
                    sender_ip = frame[28:32]
                    print(
                        "listener: ARP request from %s %s"
                        % (sender_mac.hex(":"), ".".join(map(str, sender_ip))),
                        flush=True,
                    )
                    if not echoed:
                        # Build an ARP reply addressed back to the sender.
                        reply = bytearray(42)
                        reply[0:6] = sender_mac
                        reply[6:12] = bytes.fromhex("525400123402")  # gateway MAC
                        reply[12:14] = b"\x08\x06"
                        reply[14:16] = b"\x00\x01"
                        reply[16:18] = b"\x08\x00"
                        reply[18] = 6
                        reply[19] = 4
                        reply[20:22] = b"\x00\x02"  # op: reply
                        reply[22:28] = reply[6:12]  # gateway hw
                        reply[28:32] = bytes([10, 0, 2, 2])  # gateway proto
                        reply[32:38] = sender_mac  # target hw
                        reply[38:42] = sender_ip  # target proto
                        conn.sendall(struct.pack(">I", len(reply)) + reply)
                        echoed = True
                        print("listener: echoed ARP reply (42 bytes)", flush=True)
                elif op == b"\x00\x02":
                    print("listener: ARP reply from guest", flush=True)
            else:
                print(
                    "listener: frame %d, %d bytes, proto %s"
                    % (total, len(frame), proto.hex()),
                    flush=True,
                )

    with pcap:
        print(f"listener: wrote {total} frame(s) to {outfile}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())