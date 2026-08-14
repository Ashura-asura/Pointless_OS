#!/usr/bin/env python3
"""Host-side capture + peer for the Aegis network-stack demo (Phase E).

QEMU is launched with `-nic socket,connect=127.0.0.1:PORT,model=e1000e,...`
(an external helper, like this script, accepts the connection).
Each packet on the socket netdev is framed as: uint32 big-endian length,
then the raw Ethernet frame bytes (net/socket.c `net_socket_receive`).

This process:
  1. listens on 127.0.0.1:PORT and accepts QEMU's connection,
  2. reads every frame and writes it to a pcap (link type 1, Ethernet),
  3. answers the kernel's gateway ARP request (10.0.2.2) with an ARP reply,
  4. acts as a minimal TCP server on 10.0.2.2:8080: it completes a real
     three-way handshake (SYN -> SYN-ACK -> ACK), acknowledges the kernel's
     HTTP request and replies with a real HTTP response, and acknowledges
     the kernel's FIN. Correct IPv4 + TCP checksums are computed so the
     kernel's checksum-verifying parser accepts every frame,
  5. acts as a real TLS 1.3 server on 10.0.2.2:8443 (OpenSSL behind memory
     BIOs, self-signed RSA cert): it completes the TCP handshake, feeds the
     kernel's ClientHello record into OpenSSL, relays the server flight back,
     and cross-checks the X25519 ECDHE shared secret on the host side.

Usage: python e1000_host_listener.py PORT OUTFILE.pcap
"""

import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

# The peer the kernel will talk to.  The kernel resolves this gateway over ARP,
# so frames FROM us must carry the gateway MAC/IP and frames TO us must be
# addressed to the guest MAC/IP.
GUEST_MAC = bytes.fromhex("525400123456")
GUEST_IP = bytes([10, 0, 2, 15])
GATEWAY_MAC = bytes.fromhex("525400123402")
GATEWAY_IP = bytes([10, 0, 2, 2])
SERVER_PORT = 8080
TLS_PORT = 8443

# The kernel's documented fixed ephemeral scalar (no CSPRNG in the guest).
# We recompute the ECDHE shared secret on our side with the same scalar, so
# the value the kernel derives must match this byte-for-byte.
EPHEMERAL_SCALAR = bytes.fromhex(
    "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
)

HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"Content-Length: 47\r\n"
    b"\r\n"
    b"Aegis kernel TCP demo: hello from the host peer!\r\n"
)


def x25519_ref(scalar_bytes, u_bytes):
    """RFC 7748 X25519 reference (validated against the published vectors)."""
    p = 2**255 - 19
    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k[t >> 3] >> (t & 7)) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        aa = (x2 + z2) ** 2 % p
        bb = (x2 - z2) ** 2 % p
        e = (aa - bb) % p
        da = (x3 - z3) * (x2 + z2) % p
        cb = (x3 + z3) * (x2 - z2) % p
        x3 = (da + cb) ** 2 % p
        z3 = (x1 * (da - cb) ** 2) % p
        x2 = aa * bb % p
        z2 = (e * (aa + 121665 * e)) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, p - 2, p)) % p).to_bytes(32, "little")


def checksum(data: bytes) -> int:
    """RFC 1071 ones'-complement checksum over an even-length buffer."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_checksum(header: bytes) -> int:
    return checksum(header)


def tcp_checksum(src_ip: bytes, dst_ip: bytes, segment: bytes) -> int:
    """TCP checksum over the IPv4 pseudo-header + segment (checksum field 0)."""
    pseudo = src_ip + dst_ip + bytes([0, 6]) + struct.pack(">H", len(segment))
    return checksum(pseudo + segment)


def build_tcp_frame(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    """Assemble an Ethernet + IPv4 + TCP frame with valid checksums."""
    seg_len = 20 + len(payload)
    seg = bytearray(seg_len)
    seg[0:2] = struct.pack(">H", src_port)
    seg[2:4] = struct.pack(">H", dst_port)
    seg[4:8] = struct.pack(">I", seq)
    seg[8:12] = struct.pack(">I", ack)
    seg[12] = 5 << 4  # data offset 5, no options
    seg[13] = flags
    seg[14:16] = struct.pack(">H", 8192)  # window
    seg[16:18] = b"\x00\x00"  # checksum placeholder
    seg[20:] = payload
    ck = tcp_checksum(src_ip, dst_ip, bytes(seg))
    seg[16:18] = struct.pack(">H", ck)

    ip_len = 20 + seg_len
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack(">H", ip_len)
    ip[8] = 64  # ttl
    ip[9] = 6  # TCP
    ip[12:16] = src_ip
    ip[16:20] = dst_ip
    ip[10:12] = struct.pack(">H", ipv4_checksum(bytes(ip)))

    # Ethernet II header: destination first, then source, then ethertype.
    return dst_mac + src_mac + b"\x08\x00" + bytes(ip) + bytes(seg)


def parse_ipv4_tcp(frame: bytes):
    """Return (src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)."""
    ip = frame[14:]
    src_ip = ip[12:16]
    dst_ip = ip[16:20]
    tcp_off = 14 + ((ip[0] & 0x0F) * 4)
    tcp = frame[tcp_off:]
    src_port, dst_port = struct.unpack(">HH", tcp[0:4])
    seq, ack = struct.unpack(">II", tcp[4:12])
    flags = tcp[13]
    hlen = (tcp[12] >> 4) * 4
    payload = tcp[hlen:]
    return src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload


def _crosscheck_tls(flight: bytes) -> None:
    """Parse the server's X25519 keyshare out of the ServerHello we sent and
    derive the ECDHE shared secret using the kernel's documented scalar."""
    pos = 0
    while pos + 5 <= len(flight):
        ct = flight[pos]
        rlen = struct.unpack(">H", flight[pos + 3 : pos + 5])[0]
        frag = flight[pos + 5 : pos + 5 + rlen]
        if ct == 22 and frag[0:1] == b"\x02":  # handshake, ServerHello
            body = frag[4:]
            if len(body) < 39:
                return
            sid_len = body[34]
            p = 35 + sid_len
            if p + 3 > len(body):
                return
            q = p + 3
            if q + 2 > len(body):
                return
            ext_len = struct.unpack(">H", body[q : q + 2])[0]
            r = q + 2
            end = r + ext_len
            if end > len(body):
                return
            keyshare = None
            while r < end:
                et = struct.unpack(">H", body[r : r + 2])[0]
                elen = struct.unpack(">H", body[r + 2 : r + 4])[0]
                if et == 0x0033 and elen == 36:
                    # single KeyShareEntry: group(2) + u16 keylen + key(32)
                    if body[r + 4 : r + 6] == b"\x00\x1d" and body[r + 6 : r + 8] == b"\x00\x20":
                        keyshare = body[r + 8 : r + 40]
                r += 4 + elen
            if keyshare:
                shared = x25519_ref(EPHEMERAL_SCALAR, keyshare)
                print("listener: ECDHE shared secret (host side): %s" % shared.hex(), flush=True)
                print(
                    "listener: server keyshare: %s" % keyshare.hex(),
                    flush=True,
                )
            return
        pos += 5 + rlen


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

    # Host->guest frames (what the peer writes onto the wire), recorded
    # separately so we can see exactly what the guest should be receiving.
    host_tx = open(outfile + "-host-tx.pcap", "wb")
    host_tx.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    # TCP server state, keyed by listen port: each connection the kernel
    # opens (8080 HTTP, then 8443 TLS) gets its own ISN + seq bookkeeping.
    ports = [SERVER_PORT, TLS_PORT]
    states = {}
    for p in ports:
        states[p] = {
            "server_isn": 0x10000000 + p,
            "server_seq": 0x10000000 + p,
            "client_isn": None,
            "handshake_done": False,
            "served": False,
        }

    # TLS 1.3 server (real OpenSSL via memory BIOs). We generate a throwaway
    # self-signed RSA cert so the server can complete a real handshake.
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as td:
        cert_path = os.path.join(td, "cert.pem")
        key_path = os.path.join(td, "key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-subj", "/CN=aegis-host",
            ],
            check=True,
            capture_output=True,
        )
        tls_ctx.load_cert_chain(cert_path, key_path)
    tls_in = ssl.MemoryBIO()
    tls_out = ssl.MemoryBIO()
    tls_server = tls_ctx.wrap_bio(tls_in, tls_out, server_side=True)

    def send(frame: bytes) -> None:
        conn.sendall(struct.pack(">I", len(frame)) + frame)
        ts = struct.pack("<II", 0, 0)
        host_tx.write(ts)
        host_tx.write(struct.pack("<II", len(frame), len(frame)))
        host_tx.write(frame)
        host_tx.flush()

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

            # Record every frame in the pcap, flushing each time so the pcap
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
                        reply = bytearray(42)
                        reply[0:6] = sender_mac
                        reply[6:12] = GATEWAY_MAC
                        reply[12:14] = b"\x08\x06"
                        reply[14:16] = b"\x00\x01"
                        reply[16:18] = b"\x08\x00"
                        reply[18] = 6
                        reply[19] = 4
                        reply[20:22] = b"\x00\x02"
                        reply[22:28] = GATEWAY_MAC
                        reply[28:32] = GATEWAY_IP
                        reply[32:38] = sender_mac
                        reply[38:42] = sender_ip
                        send(bytes(reply))
                        echoed = True
                        print("listener: echoed ARP reply (42 bytes)", flush=True)
                elif op == b"\x00\x02":
                    print("listener: ARP reply from guest", flush=True)
                continue

            if proto != b"\x08\x00" or len(frame) < 34:
                print(
                    "listener: frame %d, %d bytes, proto %s"
                    % (total, len(frame), proto.hex()),
                    flush=True,
                )
                continue

            try:
                src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload = parse_ipv4_tcp(
                    frame
                )
            except (struct.error, IndexError):
                print("listener: frame %d: short/malformed IPv4", total, flush=True)
                continue

            if dst_port not in states:
                print(
                    "listener: frame %d: TCP to port %d (ignored)" % (total, dst_port),
                    flush=True,
                )
                continue

            st = states[dst_port]

            # ---- minimal TCP server state machine (per listen port) ----
            if flags & 0x02 and not st["handshake_done"]:  # SYN
                st["client_isn"] = seq
                st["server_seq"] = st["server_isn"]
                send(
                    build_tcp_frame(
                        GATEWAY_MAC,
                        GUEST_MAC,
                        GATEWAY_IP,
                        GUEST_IP,
                        dst_port,
                        src_port,
                        st["server_isn"],
                        st["client_isn"] + 1,
                        0x12,  # SYN|ACK
                        b"",
                    )
                )
                # The SYN consumed one sequence number: data begins at ISN+1.
                st["server_seq"] = (st["server_isn"] + 1) & 0xFFFFFFFF
                print("listener: TCP SYN to %d (isn=%d) -> SYN-ACK" % (dst_port, seq), flush=True)
            elif flags & 0x10:  # ACK set
                data = payload
                if flags & 0x02 and not st["handshake_done"]:  # retransmitted SYN
                    st["server_seq"] = (st["server_isn"] + 1) & 0xFFFFFFFF
                    send(
                        build_tcp_frame(
                            GATEWAY_MAC,
                            GUEST_MAC,
                            GATEWAY_IP,
                            GUEST_IP,
                            dst_port,
                            src_port,
                            st["server_isn"],
                            st["client_isn"] + 1,
                            0x12,
                            b"",
                        )
                    )
                    print("listener: retransmitted SYN -> SYN-ACK", flush=True)
                    continue
                if not st["handshake_done"]:
                    st["handshake_done"] = True
                    print(
                        "listener: ACK received - handshake complete (port %d)" % dst_port,
                        flush=True,
                    )
                if data:
                    print(
                        "listener: port %d data segment (%d bytes): %r"
                        % (dst_port, len(data), data[:64]),
                        flush=True,
                    )
                    # ACK the data.
                    send(
                        build_tcp_frame(
                            GATEWAY_MAC,
                            GUEST_MAC,
                            GATEWAY_IP,
                            GUEST_IP,
                            dst_port,
                            src_port,
                            st["server_seq"],
                            seq + len(data),
                            0x10,  # ACK
                            b"",
                        )
                    )
                    # And serve the reply (PSH|ACK).
                    if dst_port == SERVER_PORT and not st["served"]:
                        resp = HTTP_RESPONSE
                        send(
                            build_tcp_frame(
                                GATEWAY_MAC,
                                GUEST_MAC,
                                GATEWAY_IP,
                                GUEST_IP,
                                dst_port,
                                src_port,
                                st["server_seq"],
                                seq + len(data),
                                0x18,  # PSH|ACK
                                resp,
                            )
                        )
                        st["server_seq"] = (st["server_seq"] + len(resp)) & 0xFFFFFFFF
                        st["served"] = True
                        print("listener: HTTP response sent (%d bytes)" % len(resp), flush=True)
                    elif dst_port == TLS_PORT and not st["served"]:
                        # The kernel's data is a TLS 1.3 ClientHello record.
                        tls_in.write(bytes(data))
                        for _ in range(5):
                            try:
                                tls_server.do_handshake()
                            except ssl.SSLWantReadError:
                                pass
                        flight = tls_out.read()
                        if flight:
                            send(
                                build_tcp_frame(
                                    GATEWAY_MAC,
                                    GUEST_MAC,
                                    GATEWAY_IP,
                                    GUEST_IP,
                                    dst_port,
                                    src_port,
                                    st["server_seq"],
                                    seq + len(data),
                                    0x18,  # PSH|ACK
                                    flight,
                                )
                            )
                            st["server_seq"] = (st["server_seq"] + len(flight)) & 0xFFFFFFFF
                            st["served"] = True
                            print(
                                "listener: TLS server flight sent (%d bytes)" % len(flight),
                                flush=True,
                            )
                            # Cross-check the ECDHE shared secret: extract the
                            # server's X25519 keyshare from the ServerHello we
                            # just generated and derive the same value the
                            # kernel should be computing.
                            _crosscheck_tls(flight)
                        else:
                            print(
                                "listener: TLS handshake produced no output yet",
                                flush=True,
                            )
                elif flags & 0x01:  # FIN|ACK
                    send(
                        build_tcp_frame(
                            GATEWAY_MAC,
                            GUEST_MAC,
                            GATEWAY_IP,
                            GUEST_IP,
                            dst_port,
                            src_port,
                            st["server_seq"],
                            seq + 1,
                            0x10,  # ACK
                            b"",
                        )
                    )
                    print("listener: FIN acknowledged (port %d)" % dst_port, flush=True)
            else:
                print(
                    "listener: frame %d: unhandled TCP flags 0x%02x" % (total, flags),
                    flush=True,
                )

    with pcap:
        print(f"listener: wrote {total} frame(s) to {outfile}", flush=True)
    host_tx.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())