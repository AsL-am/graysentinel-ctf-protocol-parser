#!/usr/bin/env python3
"""
GraySentinel CTF – Challenge 4: Ghost Protocol
Custom XOR-encrypted UDP protocol server.
Players must reverse-engineer the protocol to extract the flag.

Usage: python3 challenge_server.py
"""

import socket
import struct
import time
import hashlib

# ─── Protocol Spec (hidden from players) ───────────────────────────────────────
#
#  PACKET STRUCTURE (all fields big-endian):
#  ┌──────────┬──────────┬──────────┬──────────┬──────────────────┬──────────┐
#  │ Magic    │ Version  │ Seq No   │ Cmd      │ Payload (XOR'd)  │ Checksum │
#  │ 2 bytes  │ 1 byte   │ 2 bytes  │ 1 byte   │ variable         │ 4 bytes  │
#  └──────────┴──────────┴──────────┴──────────┴──────────────────┴──────────┘
#
#  Magic    : 0xGS (0x4753) – "GS" for GraySentinel
#  Version  : 0x01
#  Seq No   : packet sequence number (uint16)
#  Cmd      : 0x01 = HELLO, 0x02 = REQUEST_FLAG, 0x03 = ACK
#  Payload  : XOR-encrypted with key derived from Seq No
#  Checksum : CRC32 of (Magic + Version + Seq + Cmd + raw_payload)
#
#  XOR KEY DERIVATION:
#  key_byte = (seq_no & 0xFF) ^ 0x5A
#  Each payload byte XOR'd with key_byte
# ───────────────────────────────────────────────────────────────────────────────

MAGIC        = 0x4753          # "GS"
VERSION      = 0x01
HOST         = "0.0.0.0"
PORT         = 9999
FLAG         = "GRAYSENTINEL{x0r_pr0t0c0l_r3v3rs3d_by_ghost}"

CMD_HELLO        = 0x01
CMD_REQUEST_FLAG = 0x02
CMD_ACK          = 0x03
CMD_FLAG_RESP    = 0x04
CMD_ERROR        = 0xFF

SESSIONS = {}  # seq_no -> state


def xor_encrypt(data: bytes, seq_no: int) -> bytes:
    key = (seq_no & 0xFF) ^ 0x5A
    return bytes([b ^ key for b in data])


def xor_decrypt(data: bytes, seq_no: int) -> bytes:
    return xor_encrypt(data, seq_no)  # XOR is symmetric


def checksum(data: bytes) -> int:
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def build_packet(seq_no: int, cmd: int, payload: bytes) -> bytes:
    header = struct.pack(">HBHBx", MAGIC, VERSION, seq_no, cmd)  # 7 bytes + 1 pad
    header = struct.pack(">HHBB", MAGIC, VERSION, seq_no, cmd)   # 6 bytes
    encrypted_payload = xor_encrypt(payload, seq_no)
    chk = checksum(header + encrypted_payload)
    return header + encrypted_payload + struct.pack(">I", chk)


def parse_packet(data: bytes):
    """Returns (magic, version, seq_no, cmd, decrypted_payload) or raises."""
    if len(data) < 10:
        raise ValueError("Packet too short")

    magic, version, seq_no, cmd = struct.unpack(">HHBB", data[:6])
    encrypted_payload = data[6:-4]
    recv_checksum = struct.unpack(">I", data[-4:])[0]

    # Validate magic
    if magic != MAGIC:
        raise ValueError(f"Bad magic: 0x{magic:04X}")

    # Validate version
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    # Validate checksum
    calc_chk = checksum(data[:6] + encrypted_payload)
    if calc_chk != recv_checksum:
        raise ValueError(f"Checksum mismatch: got {recv_checksum:#010x}, expected {calc_chk:#010x}")

    payload = xor_decrypt(encrypted_payload, seq_no)
    return magic, version, seq_no, cmd, payload


def handle_packet(data: bytes, addr):
    try:
        magic, version, seq_no, cmd, payload = parse_packet(data)
        msg = payload.decode("utf-8", errors="replace").strip()
        print(f"[+] {addr} | seq={seq_no} cmd=0x{cmd:02X} payload={repr(msg)}")

        if cmd == CMD_HELLO:
            resp_payload = b"WELCOME_TO_GHOST_PROTOCOL"
            SESSIONS[seq_no] = "HELLO_DONE"
            return build_packet(seq_no + 1, CMD_ACK, resp_payload)

        elif cmd == CMD_REQUEST_FLAG:
            if SESSIONS.get(seq_no - 1) == "HELLO_DONE":
                return build_packet(seq_no + 1, CMD_FLAG_RESP, FLAG.encode())
            else:
                return build_packet(seq_no + 1, CMD_ERROR, b"SEQUENCE_ERROR:SEND_HELLO_FIRST")

        else:
            return build_packet(seq_no + 1, CMD_ERROR, b"UNKNOWN_COMMAND")

    except ValueError as e:
        print(f"[-] {addr} | Parse error: {e}")
        # Send raw error (no encryption, so player can see it)
        err_msg = f"ERR:{e}".encode()
        return build_packet(0, CMD_ERROR, err_msg)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[*] GraySentinel Ghost Protocol Server listening on UDP {HOST}:{PORT}")
    print(f"[*] Magic: 0x{MAGIC:04X} | Version: {VERSION}")
    print(f"[*] Waiting for packets...\n")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            print(f"[>] Raw packet from {addr}: {data.hex()}")
            response = handle_packet(data, addr)
            if response:
                sock.sendto(response, addr)
                print(f"[<] Sent response to {addr}: {response.hex()}\n")
        except KeyboardInterrupt:
            print("\n[*] Server shutting down.")
            break
        except Exception as e:
            print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()
