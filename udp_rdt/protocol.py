from __future__ import annotations
import struct
import zlib
from dataclasses import dataclass
from typing import Iterable, List, Tuple

VERSION = 1

T_GET  = 0x01
T_DATA = 0x02
T_END  = 0x03
T_ERR  = 0x7F
T_NACK = 0x11
T_OK   = 0x12

F_FINAL = 0x01

DEFAULT_SEGMENT_SIZE = 1200
MAX_UDP_PAYLOAD = 1472

GET_HDR = ">BBBH"
GET_HDR_SIZE = struct.calcsize(GET_HDR)

DATA_HDR = ">BBBBIQQHI"
DATA_HDR_SIZE = struct.calcsize(DATA_HDR)

END_HDR = ">BBBII"
END_HDR_SIZE = struct.calcsize(END_HDR)

ERR_HDR = ">BBB H"
ERR_HDR_SIZE = struct.calcsize(">BBBH")

NACK_HDR = ">BBB H"
NACK_HDR_SIZE = struct.calcsize(">BBBH")


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def pack_get(filename: str) -> bytes:
    name_b = filename.encode("utf-8")
    hdr = struct.pack(GET_HDR, T_GET, VERSION, 0, len(name_b))
    return hdr + name_b


def unpack_get(data: bytes) -> str:
    if len(data) < GET_HDR_SIZE:
        raise ValueError("GET muito curto")
    t, v, flags, name_len = struct.unpack(GET_HDR, data[:GET_HDR_SIZE])
    if t != T_GET or v != VERSION:
        raise ValueError("GET inválido")
    name_b = data[GET_HDR_SIZE:GET_HDR_SIZE+name_len]
    return name_b.decode("utf-8")


def pack_data(win_id: int, seq: int, total_size: int, offset: int, payload: bytes, flags: int = 0) -> bytes:
    payload_len = len(payload)
    header_wo_crc = struct.pack(
        ">BBBBIQQH",
        T_DATA, VERSION, flags, win_id & 0xFF, seq, total_size, offset, payload_len
    )
    csum = crc32(header_wo_crc + payload)
    header = struct.pack(
        DATA_HDR,
        T_DATA, VERSION, flags, win_id & 0xFF, seq, total_size, offset, payload_len, csum
    )
    return header + payload


def unpack_data(data: bytes) -> Tuple[int, int, int, int, int, bytes, bool]:
    if len(data) < DATA_HDR_SIZE:
        raise ValueError("DATA muito curto")
    t, v, flags, win_id, seq, total_size, offset, payload_len, rx_crc = struct.unpack(DATA_HDR, data[:DATA_HDR_SIZE])
    if t != T_DATA or v != VERSION:
        raise ValueError("DATA inválido")
    payload = data[DATA_HDR_SIZE:DATA_HDR_SIZE+payload_len]
    calc_crc = crc32(data[:DATA_HDR_SIZE-4] + payload)
    if rx_crc != calc_crc:
        raise ValueError("Checksum incorreto")
    is_final = (flags & F_FINAL) != 0
    return win_id, seq, total_size, offset, payload_len, payload, is_final


def pack_end(total_segments: int, file_crc32: int) -> bytes:
    return struct.pack(END_HDR, T_END, VERSION, F_FINAL, total_segments, file_crc32)


def unpack_end(data: bytes) -> Tuple[int, int]:
    if len(data) < END_HDR_SIZE:
        raise ValueError("END muito curto")
    t, v, flags, total_segments, file_crc = struct.unpack(END_HDR, data[:END_HDR_SIZE])
    if t != T_END or v != VERSION:
        raise ValueError("END inválido")
    return total_segments, file_crc


def pack_err(code: int, msg: str) -> bytes:
    b = msg.encode("utf-8")
    hdr = struct.pack(ERR_HDR, T_ERR, VERSION, code, len(b))
    return hdr + b


def unpack_err(data: bytes) -> Tuple[int, str]:
    if len(data) < ERR_HDR_SIZE:
        raise ValueError("ERR muito curto")
    t, v, code, mlen = struct.unpack(ERR_HDR, data[:ERR_HDR_SIZE])
    if t != T_ERR or v != VERSION:
        raise ValueError("ERR inválido")
    msg = data[ERR_HDR_SIZE:ERR_HDR_SIZE+mlen].decode("utf-8")
    return code, msg


def pack_nack(missing: Iterable[int]) -> bytes:
    seqs = list(missing)
    hdr = struct.pack(NACK_HDR, T_NACK, VERSION, 0, len(seqs))
    body = b"".join(struct.pack(">I", s) for s in seqs)
    return hdr + body


def unpack_nack(data: bytes) -> List[int]:
    if len(data) < NACK_HDR_SIZE:
        raise ValueError("NACK muito curto")
    t, v, flags, count = struct.unpack(NACK_HDR, data[:NACK_HDR_SIZE])
    if t != T_NACK or v != VERSION:
        raise ValueError("NACK inválido")
    seqs = []
    off = NACK_HDR_SIZE
    for _ in range(count):
        if off + 4 > len(data):
            break
        (s,) = struct.unpack(">I", data[off:off+4])
        seqs.append(s)
        off += 4
    return seqs


def pack_ok() -> bytes:
    return struct.pack(">BBB", T_OK, VERSION, 0)


def is_type(data: bytes, t: int) -> bool:
    return len(data) >= 1 and data[0] == t
