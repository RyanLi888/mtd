#!/usr/bin/env python3
"""Fake plaintext Stratum pool for local testing.

Implements a minimal Stratum protocol server over plain TCP.
Used for smoke testing the plaintext probe.

Privacy: no wallet, no real pool host.
"""

import argparse
import asyncio
import json
import os
import sys
import time


class FakePlaintextPool:
    """Minimal Stratum pool over plaintext TCP."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.job_counter = 0
        self.submit_counter = 0

    def _make_job(self):
        self.job_counter += 1
        job_id = f"job_{self.job_counter:04d}_{os.urandom(4).hex()}"
        return job_id, "0" * 152, "ffffffffffffffff"

    async def _handle(self, reader, writer):
        addr = writer.get_extra_info("peername")
        print(f"[pool] Client connected: {addr}")

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
                params = msg.get("params", [])

                if method == "mining.subscribe":
                    result = [[["mining.notify", "fake_sub_id"]], "00000000", 4]
                    resp = json.dumps({"id": req_id, "result": result, "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

                elif method == "mining.authorize":
                    resp = json.dumps({"id": req_id, "result": True, "error": None}) + "\n"
                    writer.write(resp.encode())
                    await writer.drain()

                    # Send first job
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

                    # Send next job
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
            print(f"[pool] Client disconnected: {addr}")
            writer.close()

    async def run(self):
        server = await asyncio.start_server(self._handle, self.host, self.port)
        print(f"[pool] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Fake plaintext Stratum pool")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=13000)
    args = parser.parse_args()

    pool = FakePlaintextPool(args.host, args.port)
    try:
        asyncio.run(pool.run())
    except KeyboardInterrupt:
        print(f"\n[pool] Stopped. Jobs={pool.job_counter} Submits={pool.submit_counter}")


if __name__ == "__main__":
    main()
