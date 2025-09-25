from __future__ import annotations
import argparse
import os
import socket
import threading
import zlib
from typing import Dict, Tuple

from protocol import (
    T_GET, T_NACK, T_OK, T_ERR, T_END, T_DATA,
    pack_err, is_type, unpack_get, pack_data, pack_end,
    DEFAULT_SEGMENT_SIZE, F_FINAL,
)


ClientAddr = Tuple[str, int]


def chunk_file(file_path: str, segment_size: int):
    total = os.path.getsize(file_path)
    with open(file_path, 'rb') as f:
        offset = 0
        seq = 0
        while True:
            data = f.read(segment_size)
            if not data:
                break
            yield seq, offset, data
            offset += len(data)
            seq += 1


class UDPServer:
    def __init__(self, host: str, port: int, data_dir: str, segment_size: int = DEFAULT_SEGMENT_SIZE):
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self.segment_size = max(1, min(segment_size, 1300))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(0.2)
        self.lock = threading.Lock()
        self.client_segments: Dict[ClientAddr, Dict[int, bytes]] = {}
        self.client_meta: Dict[ClientAddr, Tuple[str, int, int]] = {}
        print(f"Servidor escutando em {self.host}:{self.port} | segment_size={self.segment_size}")

    def serve_forever(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("Encerrando servidor...")
                break

            if not data:
                continue

            t = data[0]
            if t == T_GET:
                self.handle_get(data, addr)
            elif t == T_NACK:
                self.handle_nack(data, addr)
            elif t == T_OK:
                print(f"OK de {addr}, limpeza de estado")
                with self.lock:
                    self.client_segments.pop(addr, None)
                    self.client_meta.pop(addr, None)
            else:
                pass

    def handle_get(self, data: bytes, addr: ClientAddr):
        try:
            filename = unpack_get(data)
        except Exception as e:
            print(f"GET inválido de {addr}: {e}")
            return

        base_dir = os.path.abspath(self.data_dir)
        requested = os.path.normpath(filename)
        path = os.path.abspath(os.path.join(base_dir, requested))
        if not path.startswith(base_dir + os.sep):
            msg = f"Caminho inválido: {filename}"
            print(msg)
            self.sock.sendto(pack_err(0x02, msg), addr)
            return
        if not os.path.isfile(path):
            msg = f"Arquivo não encontrado: {filename}"
            print(msg)
            self.sock.sendto(pack_err(0x01, msg), addr)
            return

        total_size = os.path.getsize(path)
        file_crc = 0

        segments: Dict[int, bytes] = {}
        win_id = 0
        total_segments = 0
        for seq, offset, payload in chunk_file(path, self.segment_size):
            flags = 0
            is_last = (offset + len(payload) >= total_size)
            if is_last:
                flags |= F_FINAL
            pkt = pack_data(win_id, seq, total_size, offset, payload, flags)
            segments[seq] = pkt
            total_segments += 1
            file_crc = zlib.crc32(payload, file_crc) & 0xFFFFFFFF

        with self.lock:
            self.client_segments[addr] = segments
            self.client_meta[addr] = (filename, total_size, total_segments)

        print(f"Enviando {total_segments} segmentos ({total_size} bytes) para {addr}: {filename}")
        for seq in range(total_segments):
            self.sock.sendto(segments[seq], addr)
        self.sock.sendto(pack_end(total_segments, file_crc), addr)

    def handle_nack(self, data: bytes, addr: ClientAddr):
        from protocol import unpack_nack
        try:
            seqs = unpack_nack(data)
        except Exception as e:
            print(f"NACK inválido de {addr}: {e}")
            return

        with self.lock:
            segs = self.client_segments.get(addr)
        if not segs:
            print(f"NACK recebido mas sem estado para {addr}")
            return

        for s in seqs:
            pkt = segs.get(s)
            if pkt:
                self.sock.sendto(pkt, addr)


def main():
    ap = argparse.ArgumentParser(description="Servidor UDP - RDT simples")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--segment-size", type=int, default=DEFAULT_SEGMENT_SIZE)
    args = ap.parse_args()

    srv = UDPServer(args.host, args.port, args.data_dir, args.segment_size)
    try:
        srv.serve_forever()
    finally:
        srv.sock.close()

if __name__ == "__main__":
    main()
