#!/usr/bin/env python3
"""Environment-side worker for relay_server.py.

This script runs inside an environment that can reach:
  https://api.openai.com:18080 through http://proxy:8080

It keeps an outbound WebSocket connection to the public relay server's /env
endpoint and executes HTTP/WebSocket jobs on behalf of /api callers.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import http.client
import importlib.util
import json
import os
import queue
import random
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from typing import Any
from urllib.parse import urlsplit


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MIN_PYTHON = (3, 10)
PIP_DEPENDENCIES: list[tuple[str, str]] = []
UPSTREAM_HOST = "api.openai.com"
UPSTREAM_PORT = 18080
UPSTREAM_PROXY_HOST = "proxy"
UPSTREAM_PROXY_PORT = 8080
PLACEHOLDER_AUTH = "Bearer sk-PLACEHOLDER_API_KEY"
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def ensure_dependencies() -> None:
    if sys.version_info < MIN_PYTHON:
        raise SystemExit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; found "
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
    missing = [(module, package) for module, package in PIP_DEPENDENCIES if importlib.util.find_spec(module) is None]
    if not missing:
        return
    packages = [package for _, package in missing]
    print(f"Installing missing Python packages: {', '.join(packages)}", flush=True)
    subprocess.check_call([sys.executable, "-m", "pip", "install", *packages])


def set_tcp_nodelay(sock: Any) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str | None) -> bytes:
    return base64.b64decode(data or "")


def make_ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def mask_payload(payload: bytes, mask: bytes) -> bytes:
    return bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))


async def write_ws_frame(
    writer: asyncio.StreamWriter,
    opcode: int,
    payload: bytes = b"",
    *,
    mask: bool,
) -> None:
    first = 0x80 | (opcode & 0x0F)
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length < 126:
        header = bytes([first, mask_bit | length])
    elif length < 65536:
        header = bytes([first, mask_bit | 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([first, mask_bit | 127]) + length.to_bytes(8, "big")
    if mask:
        key = os.urandom(4)
        writer.write(header + key + mask_payload(payload, key))
    else:
        writer.write(header + payload)
    await writer.drain()


async def read_ws_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    b1, b2 = await reader.readexactly(2)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), "big")
    key = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length) if length else b""
    if masked:
        payload = mask_payload(payload, key)
    return opcode, payload


def write_blocking_ws_frame(sock: ssl.SSLSocket, opcode: int, payload: bytes = b"", *, mask: bool = True) -> None:
    first = 0x80 | (opcode & 0x0F)
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length < 126:
        header = bytes([first, mask_bit | length])
    elif length < 65536:
        header = bytes([first, mask_bit | 126]) + struct.pack("!H", length)
    else:
        header = bytes([first, mask_bit | 127]) + struct.pack("!Q", length)
    if mask:
        key = os.urandom(4)
        sock.sendall(header + key + mask_payload(payload, key))
    else:
        sock.sendall(header + payload)


def recv_exact(sock: ssl.SSLSocket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data


def read_blocking_ws_frame(sock: ssl.SSLSocket) -> tuple[int, bytes]:
    b1, b2 = recv_exact(sock, 2)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    if masked:
        payload = mask_payload(payload, key)
    return opcode, payload


def filtered_headers(headers: list[list[str]] | list[tuple[str, str]], *, websocket: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers:
        lname = str(name).lower()
        if lname in HOP_BY_HOP or lname in {"host", "content-length"}:
            continue
        if websocket and lname in {
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-accept",
        }:
            continue
        out[str(name)] = str(value)
    if not any(name.lower() == "authorization" for name in out):
        out["Authorization"] = PLACEHOLDER_AUTH
    return out


class RelayClient:
    def __init__(self, args: argparse.Namespace) -> None:
        self.server_url = args.server
        base_worker_id = args.worker_id or "env"
        self.worker_id = f"{base_worker_id}-{secrets.token_hex(5)}"
        self.fake_upstream = args.fake_upstream
        self.fake_stream_delay = args.fake_stream_delay
        self.outgoing: asyncio.Queue[dict[str, Any]] | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.writer_lock: asyncio.Lock | None = None
        self.ws_jobs: dict[str, "WsUpstreamJob"] = {}
        self.stop = threading.Event()

    async def run_forever(self) -> None:
        backoff = 1.0
        while True:
            try:
                await self.run_once()
                backoff = 1.0
            except Exception as exc:
                print(f"relay connection ended: {type(exc).__name__}: {exc}", flush=True)
            await asyncio.sleep(backoff + random.random())
            backoff = min(backoff * 1.7, 20.0)

    async def run_once(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.outgoing = asyncio.Queue()
        reader, writer = await self.connect_ws()
        self.writer_lock = asyncio.Lock()
        sender = asyncio.create_task(self.sender(writer))
        ping = asyncio.create_task(self.ping(writer))

        def close_on_task_error(task: asyncio.Task) -> None:
            try:
                exc = task.exception()
            except asyncio.CancelledError:
                return
            if exc:
                writer.close()

        sender.add_done_callback(close_on_task_error)
        ping.add_done_callback(close_on_task_error)
        await self.send(
            {
                "type": "hello",
                "worker_id": self.worker_id,
            }
        )
        print(f"connected to relay as {self.worker_id}", flush=True)
        try:
            while True:
                opcode, payload = await read_ws_frame(reader)
                if opcode == 8:
                    raise ConnectionError("server closed websocket")
                if opcode == 9:
                    await write_ws_frame(writer, 10, payload, mask=True)
                    continue
                if opcode != 1:
                    continue
                try:
                    msg = json.loads(payload.decode("utf-8"))
                    await self.handle_message(msg)
                except Exception as exc:
                    print(f"bad relay message: {type(exc).__name__}: {exc}", flush=True)
        finally:
            ping.cancel()
            sender.cancel()
            for job in list(self.ws_jobs.values()):
                job.close()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def connect_ws(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        split = urlsplit(self.server_url)
        if split.scheme not in {"ws", "wss"}:
            raise ValueError("--server must be ws:// or wss://")
        host = split.hostname or "localhost"
        port = split.port or (443 if split.scheme == "wss" else 80)
        path = split.path or "/env"
        if split.query:
            path += "?" + split.query
        ssl_context = ssl.create_default_context() if split.scheme == "wss" else None
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
        sock = writer.get_extra_info("socket")
        if sock is not None:
            set_tcp_nodelay(sock)
        key = make_ws_key()
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        status_line = await reader.readline()
        if b"101" not in status_line:
            rest = await reader.read()
            raise ConnectionError((status_line + rest).decode("utf-8", "replace"))
        while True:
            line = await reader.readline()
            if line in {b"\r\n", b"\n", b""}:
                break
        return reader, writer

    async def sender(self, writer: asyncio.StreamWriter) -> None:
        assert self.outgoing is not None
        while True:
            msg = await self.outgoing.get()
            assert self.writer_lock is not None
            async with self.writer_lock:
                await write_ws_frame(
                    writer,
                    1,
                    json.dumps(msg, separators=(",", ":")).encode("utf-8"),
                    mask=True,
                )

    async def ping(self, writer: asyncio.StreamWriter) -> None:
        while True:
            await asyncio.sleep(30)
            assert self.writer_lock is not None
            async with self.writer_lock:
                await write_ws_frame(writer, 9, b"", mask=True)

    async def send(self, msg: dict[str, Any]) -> None:
        assert self.outgoing is not None
        await self.outgoing.put(msg)

    def send_from_thread(self, msg: dict[str, Any]) -> None:
        if not self.loop or not self.outgoing:
            return
        self.loop.call_soon_threadsafe(self.outgoing.put_nowait, msg)

    async def handle_message(self, msg: dict[str, Any]) -> None:
        typ = msg.get("type")
        job_id = msg.get("job_id")
        if typ == "http_request" and job_id:
            threading.Thread(target=self.run_http_job, args=(msg,), daemon=True).start()
        elif typ == "ws_request" and job_id:
            job = WsUpstreamJob(self, msg)
            self.ws_jobs[job_id] = job
            job.start()
        elif typ == "ws_frame" and job_id:
            job = self.ws_jobs.get(job_id)
            if job:
                job.put_frame(int(msg.get("opcode") or 1), unb64(msg.get("data")))
        elif typ == "cancel" and job_id:
            job = self.ws_jobs.pop(job_id, None)
            if job:
                job.close()

    def run_http_job(self, msg: dict[str, Any]) -> None:
        if self.fake_upstream:
            self.run_fake_http_job(msg)
            return
        job_id = msg["job_id"]
        conn: http.client.HTTPSConnection | None = None
        try:
            method = msg.get("method") or "POST"
            path = msg.get("path") or "/v1/responses"
            body = unb64(msg.get("body"))
            headers = filtered_headers(msg.get("headers") or [], websocket=False)
            conn = http.client.HTTPSConnection(UPSTREAM_PROXY_HOST, UPSTREAM_PROXY_PORT, timeout=None)
            conn.set_tunnel(UPSTREAM_HOST, UPSTREAM_PORT)
            conn.request(method, path, body=body if body else None, headers=headers)
            if conn.sock is not None:
                set_tcp_nodelay(conn.sock)
            resp = conn.getresponse()
            headers_list = [[k, v] for k, v in resp.getheaders()]
            content_type = ""
            for k, v in headers_list:
                if k.lower() == "content-type":
                    content_type = v.lower()
                    break
            is_stream = content_type.startswith("text/event-stream")
            if is_stream:
                self.send_from_thread(
                    {
                        "type": "http_start",
                        "job_id": job_id,
                        "status": resp.status,
                        "reason": resp.reason,
                        "headers": headers_list,
                    }
                )
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    self.send_from_thread({"type": "http_body", "job_id": job_id, "data": b64(chunk)})
                self.send_from_thread({"type": "http_end", "job_id": job_id})
            else:
                chunks: list[bytes] = []
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                self.send_from_thread(
                    {
                        "type": "http_start",
                        "job_id": job_id,
                        "status": resp.status,
                        "reason": resp.reason,
                        "headers": headers_list,
                    }
                )
                if chunks:
                    self.send_from_thread({"type": "http_body", "job_id": job_id, "data": b64(b"".join(chunks))})
                self.send_from_thread({"type": "http_end", "job_id": job_id})
        except Exception as exc:
            self.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    def run_fake_http_job(self, msg: dict[str, Any]) -> None:
        job_id = msg["job_id"]
        try:
            body = unb64(msg.get("body"))
            wants_stream = False
            try:
                parsed = json.loads(body.decode("utf-8")) if body else {}
                wants_stream = bool(parsed.get("stream"))
            except Exception:
                parsed = {}
            if wants_stream:
                self.send_from_thread(
                    {
                        "type": "http_start",
                        "job_id": job_id,
                        "status": 200,
                        "reason": "OK",
                        "headers": [["Content-Type", "text/event-stream; charset=utf-8"]],
                    }
                )
                events = [
                    'event: response.created\ndata: {"type":"response.created"}\n\n',
                    f'event: response.output_text.delta\ndata: {json.dumps({"type":"response.output_text.delta","delta":self.worker_id})}\n\n',
                    'event: response.completed\ndata: {"type":"response.completed","response":{"status":"completed"}}\n\n',
                ]
                for event in events:
                    time.sleep(self.fake_stream_delay)
                    self.send_from_thread({"type": "http_body", "job_id": job_id, "data": b64(event.encode())})
                self.send_from_thread({"type": "http_end", "job_id": job_id})
                return
            response = {
                "object": "response",
                "status": "completed",
                "model": parsed.get("model", "fake-model") if isinstance(parsed, dict) else "fake-model",
                "worker_id": self.worker_id,
                "job_id": job_id,
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": self.worker_id}],
                    }
                ],
            }
            data = json.dumps(response, separators=(",", ":")).encode("utf-8")
            self.send_from_thread(
                {
                    "type": "http_start",
                    "job_id": job_id,
                    "status": 200,
                    "reason": "OK",
                    "headers": [["Content-Type", "application/json"]],
                }
            )
            self.send_from_thread({"type": "http_body", "job_id": job_id, "data": b64(data)})
            self.send_from_thread({"type": "http_end", "job_id": job_id})
        except Exception as exc:
            self.send_from_thread({"type": "job_error", "job_id": job_id, "message": str(exc)})


class WsUpstreamJob:
    def __init__(self, relay: RelayClient, msg: dict[str, Any]) -> None:
        self.relay = relay
        self.msg = msg
        self.job_id = msg["job_id"]
        self.outbound: queue.Queue[tuple[int, bytes] | None] = queue.Queue()
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def put_frame(self, opcode: int, payload: bytes) -> None:
        self.outbound.put((opcode, payload))

    def close(self) -> None:
        self.closed.set()
        self.outbound.put(None)

    def run(self) -> None:
        if self.relay.fake_upstream:
            self.run_fake()
            return
        sock: ssl.SSLSocket | None = None
        try:
            sock, response_headers = self.connect_upstream()
            self.relay.send_from_thread(
                {"type": "ws_open", "job_id": self.job_id, "headers": [[k, v] for k, v in response_headers.items()]}
            )
            while not self.closed.is_set():
                self.drain_outbound(sock)
                try:
                    readable, _, _ = select.select([sock], [], [], 0.1)
                except Exception:
                    readable = []
                if readable or sock.pending():
                    opcode, payload = read_blocking_ws_frame(sock)
                    if opcode == 9:
                        write_blocking_ws_frame(sock, 10, payload, mask=True)
                    self.relay.send_from_thread(
                        {"type": "ws_frame", "job_id": self.job_id, "opcode": opcode, "data": b64(payload)}
                    )
                    if opcode == 8:
                        break
            self.relay.send_from_thread({"type": "ws_close", "job_id": self.job_id, "code": 1000, "reason": ""})
        except Exception as exc:
            self.relay.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": self.job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )
        finally:
            self.relay.ws_jobs.pop(self.job_id, None)
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    def drain_outbound(self, sock: ssl.SSLSocket) -> None:
        while True:
            try:
                item = self.outbound.get_nowait()
            except queue.Empty:
                return
            if item is None:
                write_blocking_ws_frame(sock, 8, (1000).to_bytes(2, "big"), mask=True)
                self.closed.set()
                return
            opcode, payload = item
            write_blocking_ws_frame(sock, opcode, payload, mask=True)
            if opcode == 8:
                self.closed.set()
                return

    def connect_upstream(self) -> tuple[ssl.SSLSocket, dict[str, str]]:
        raw = socket.create_connection((UPSTREAM_PROXY_HOST, UPSTREAM_PROXY_PORT), timeout=None)
        set_tcp_nodelay(raw)
        raw.sendall(
            (
                f"CONNECT {UPSTREAM_HOST}:{UPSTREAM_PORT} HTTP/1.1\r\n"
                f"Host: {UPSTREAM_HOST}:{UPSTREAM_PORT}\r\n"
                "Proxy-Connection: Keep-Alive\r\n\r\n"
            ).encode("ascii")
        )
        proxy_head = b""
        while b"\r\n\r\n" not in proxy_head:
            proxy_head += raw.recv(4096)
        if b" 200 " not in proxy_head.split(b"\r\n", 1)[0]:
            raise ConnectionError(proxy_head.decode("iso-8859-1", "replace"))

        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=UPSTREAM_HOST)
        key = make_ws_key()
        path = self.msg.get("path") or "/v1/responses"
        headers = filtered_headers(self.msg.get("headers") or [], websocket=True)
        headers["Host"] = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
        headers["Upgrade"] = "websocket"
        headers["Connection"] = "Upgrade"
        headers["Sec-WebSocket-Key"] = key
        headers["Sec-WebSocket-Version"] = "13"
        request = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        sock.sendall(request.encode("iso-8859-1"))
        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(4096)
        head = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        lines = head.splitlines()
        if not lines or "101" not in lines[0]:
            raise ConnectionError(head)
        response_headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                response_headers[name.strip()] = value.strip()
        return sock, response_headers

    def run_fake(self) -> None:
        self.relay.send_from_thread({"type": "ws_open", "job_id": self.job_id, "headers": []})
        try:
            while not self.closed.is_set():
                item = self.outbound.get(timeout=0.2)
                if item is None:
                    break
                opcode, payload = item
                if opcode == 8:
                    break
                if opcode == 9:
                    self.relay.send_from_thread({"type": "ws_frame", "job_id": self.job_id, "opcode": 10, "data": b64(payload)})
                    continue
                if opcode in {1, 2}:
                    events = [
                        {"type": "response.created", "response": {"status": "in_progress"}},
                        {"type": "response.output_text.delta", "delta": self.relay.worker_id},
                        {"type": "response.completed", "response": {"status": "completed", "model": "fake-model"}},
                    ]
                    for event in events:
                        time.sleep(self.relay.fake_stream_delay)
                        self.relay.send_from_thread(
                            {
                                "type": "ws_frame",
                                "job_id": self.job_id,
                                "opcode": 1,
                                "data": b64(json.dumps(event, separators=(",", ":")).encode("utf-8")),
                            }
                        )
                    break
        except queue.Empty:
            pass
        finally:
            self.relay.send_from_thread({"type": "ws_close", "job_id": self.job_id, "code": 1000, "reason": ""})
            self.relay.ws_jobs.pop(self.job_id, None)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Environment worker for relay_server.py.")
    parser.add_argument("--server", default=os.getenv("RELAY_SERVER", "ws://localhost:7860/env"))
    parser.add_argument("--worker-id", default=os.getenv("WORKER_ID"))
    parser.add_argument("--token", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--fake-upstream", action="store_true", help="Test mode: simulate upstream instead of calling OpenAI.")
    parser.add_argument("--fake-stream-delay", type=float, default=float(os.getenv("FAKE_STREAM_DELAY", "0.15")))
    return parser.parse_args()


def main() -> None:
    ensure_dependencies()
    args = parse_args()
    client = RelayClient(args)
    try:
        asyncio.run(client.run_forever())
    except KeyboardInterrupt:
        print("stopped", flush=True)


if __name__ == "__main__":
    main()
