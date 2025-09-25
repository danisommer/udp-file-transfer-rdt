from __future__ import annotations
import argparse
import os
import random
import socket
import sys
from typing import Dict, Tuple

from protocol import (
    T_DATA, T_ERR, T_END, T_GET,
    pack_get, unpack_err, unpack_data, unpack_end,
    pack_nack, pack_ok, DEFAULT_SEGMENT_SIZE
)
from utils import parse_drop_spec
import zlib


class UDPClient:
    def __init__(self, server_host: str, server_port: int, timeout: float = 1.0, drop_specs=None, drop_prob: float = 0.0):
        self.server = (server_host, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.drop_prob = drop_prob
        self.drop_map: Dict[int, bool] = {}
        for spec in (drop_specs or []):
            self.drop_map.update(parse_drop_spec(spec))
        self.already_dropped = set()

    def request_file(self, filename: str, out_path: str | None = None, segment_size: int = DEFAULT_SEGMENT_SIZE) -> bool:
        req = pack_get(filename)
        self.sock.settimeout(2)
        try:
            self.sock.sendto(req, self.server)
            data, addr = self.sock.recvfrom(65535)
        except socket.timeout:
            print("Servidor indisponível ou não respondeu. Abortando requisição.")
            return False
        self.sock.settimeout(5)
        t = data[0]

        segments: Dict[int, bytes] = {}
        total_size = None
        total_segments = None
        file_crc_from_server = None
        max_seq = -1

        timeout_count = 0
        max_timeouts = 3

        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                timeout_count = 0
            except socket.timeout:
                timeout_count += 1
                print("Timeout durante transferência ou servidor interrompido. Abortando requisição.")
                if timeout_count >= max_timeouts:
                    print(f"Abortando após {max_timeouts} timeouts consecutivos.")
                    return False
                missing = self._missing_segments(segments, total_segments)
                if missing:
                    self.sock.sendto(pack_nack(missing), self.server)
                    continue
                else:
                    if not segments:
                        self.sock.sendto(req, self.server)
                        continue
                    if total_segments is None and max_seq >= 0:
                        self.sock.sendto(pack_nack([max_seq]), self.server)
                        continue
                    print("Timeout sem progresso; abortando.")
                    return False
            t = data[0]

            if t == T_ERR:
                try:
                    code, msg = unpack_err(data)
                except Exception:
                    code, msg = 0xFF, "Erro desconhecido"
                print(f"Erro do servidor ({code}): {msg}")
                return False

            if t == T_DATA:
                try:
                    win_id, seq, tsize, offset, plen, payload, is_final = unpack_data(data)
                except Exception as e:
                    print(f"Pacote corrompido: {e}")
                    continue

                if seq in self.drop_map and seq not in self.already_dropped:
                    print(f"[DROP] Descartando seq {seq}")
                    self.already_dropped.add(seq)
                    continue

                if self.drop_prob > 0 and random.random() < self.drop_prob:
                    print(f"[DROP] Descartando seq {seq}")
                    continue

                if total_size is None:
                    total_size = tsize
                max_seq = max(max_seq, seq)
                segments[seq] = payload
                if is_final:
                    total_segments = seq + 1

                if total_segments is not None and len(segments) >= total_segments:
                    self.sock.sendto(pack_ok(), self.server)
                    break

            elif t == T_END:
                try:
                    tseg, fcrc = unpack_end(data)
                except Exception as e:
                    print(f"END inválido: {e}")
                    continue
                total_segments = tseg
                file_crc_from_server = fcrc
                if len(segments) < total_segments:
                    miss = self._missing_segments(segments, total_segments)
                    if miss:
                        print(f"Recebido END, faltam {len(miss)} segmentos -> NACK")
                        self.sock.sendto(pack_nack(miss), self.server)
                        continue
                self.sock.sendto(pack_ok(), self.server)
                break
            else:
                pass

        if not segments:
            print("Nenhum dado recebido")
            return False

        if total_segments is None:
            total_segments = max(segments.keys()) + 1

        data_bytes = b"".join(segments.get(i, b"") for i in range(total_segments))
        if total_size is not None and len(data_bytes) != total_size:
            print(f"Tamanho divergente: esperado {total_size}, obtido {len(data_bytes)}")
            return False

        if file_crc_from_server is not None:
            calc_crc = zlib.crc32(data_bytes) & 0xFFFFFFFF
            if calc_crc != file_crc_from_server:
                print(f"CRC incorreto: esperado {file_crc_from_server:08x}, obtido {calc_crc:08x}")
                return False

        if out_path is None:
            out_dir = "downloads"
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, os.path.basename(filename))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(data_bytes)
        print(f"Arquivo salvo em {out_path} ({len(data_bytes)} bytes)")
        return True

    @staticmethod
    def _missing_segments(segments: Dict[int, bytes], total_segments: int | None):
        if not segments:
            return []
        if total_segments is None:
            m = max(segments.keys())
            return [i for i in range(m + 1) if i not in segments]
        return [i for i in range(total_segments) if i not in segments]


def parse_server(spec: str) -> Tuple[str, int]:
    if ':' not in spec:
        raise ValueError("Use --server ip:porta")
    host, p = spec.rsplit(':', 1)
    return host, int(p)


def main():
    ap = argparse.ArgumentParser(description="Cliente UDP - RDT simples")
    ap.add_argument("--server", required=True, help="ip:porta do servidor")
    ap.add_argument("--file", required=True, help="nome do arquivo no servidor")
    ap.add_argument("--out", help="caminho do arquivo de saída")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--drop", action='append', help="simular perda: seq:lista,ex 1,5-9")
    ap.add_argument("--drop-prob", type=float, default=0.0)
    args = ap.parse_args()

    host, port = parse_server(args.server)
    cli = UDPClient(host, port, timeout=args.timeout, drop_specs=args.drop, drop_prob=args.drop_prob)
    ok = cli.request_file(args.file, args.out)
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
