#!/usr/bin/env python3
"""Fake TLS Stratum pool for local testing.

Implements a minimal Stratum protocol server over TLS.
Used for smoke testing the TLS probe.

Privacy: no wallet, no real pool host.
"""

import argparse
import asyncio
import json
import os
import ssl
import sys
import time


class FakeTlsPool:
    """Minimal Stratum pool over TLS."""

    def __init__(self, host: str, port: int, certfile: str, keyfile: str):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.job_counter = 0
        self.submit_counter = 0

    def _make_job(self):
        self.job_counter += 1
        job_id = f"job_{self.job_counter:04d}_{os.urandom(4).hex()}"
        return job_id, "0" * 152, "ffffffffffffffff"

    async def _handle(self, reader, writer):
        addr = writer.get_extra_info("peername")
        print(f"[tls_pool] Client connected: {addr}")

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue

                try:
                    msg = json.loads(line_str)
                except json.JSONDecodeError:
                    continue

                method = msg.get("method", "")
                req_id = msg.get("id")

                if method == "mining.subscribe":
                    result = [[["mining.notify", "fake_sub_id"]], "00000000", 4]
                    resp = json.dumps({"id": req_id, "result": result, "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

                elif method == "mining.authorize":
                    resp = json.dumps({"id": req_id, "result": True, "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

                    job_id, blob, target = self._make_job()
                    job = {
                        "job_id": job_id, "blob": blob, "target": target,
                        "difficulty": 1, "height": 300000 + self.job_counter,
                        "seed_hash": "a" * 64, "algo": "rx/0",
                    }
                    notify = json.dumps({"id": None, "method": "mining.notify", "params": job}) + "\n"
                    writer.write(notify.encode())
                    await writer.drain()

                elif method == "mining.submit":
                    self.submit_counter += 1
                    resp = json.dumps({"id": req_id, "result": True, "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

                    if self.job_counter < 10000:
                        job_id, blob, target = self._make_job()
                        job = {
                            "job_id": job_id, "blob": blob, "target": target,
                            "difficulty": 1, "height": 300000 + self.job_counter,
                            "seed_hash": "a" * 64, "algo": "rx/0",
                        }
                        notify = json.dumps({"id": None, "method": "mining.notify", "params": job}) + "\n"
                        writer.write(notify.encode())
                        await writer.drain()

                elif method == "login":
                    resp = json.dumps({"id": req_id, "result": {"id": "worker_001"}, "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

                    job_id, blob, target = self._make_job()
                    job = {
                        "job_id": job_id, "blob": blob, "target": target,
                        "difficulty": 1, "height": 300000 + self.job_counter,
                        "seed_hash": "a" * 64, "algo": "rx/0",
                    }
                    notify = json.dumps({"id": None, "method": "job", "params": job}) + "\n"
                    writer.write(notify.encode())
                    await writer.drain()

                elif method == "keepalive":
                    resp = json.dumps({"id": req_id, "result": "KEEPALIVED", "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            print(f"[tls_pool] Client disconnected: {addr}")
            writer.close()

    async def run(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.certfile, self.keyfile)

        server = await asyncio.start_server(self._handle, self.host, self.port, ssl=ctx)
        print(f"[tls_pool] Listening on {self.host}:{self.port} (TLS)")
        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Fake TLS Stratum pool")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=13000)
    parser.add_argument("--cert", type=str, required=True, help="TLS certificate path")
    parser.add_argument("--key", type=str, required=True, help="TLS key path")
    args = parser.parse_args()

    pool = FakeTlsPool(args.host, args.port, args.cert, args.key)
    try:
        asyncio.run(pool.run())
    except KeyboardInterrupt:
        print(f"\n[tls_pool] Stopped. Jobs={pool.job_counter} Submits={pool.submit_counter}")


if __name__ == "__main__":
    main()
