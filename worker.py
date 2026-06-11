#!/usr/bin/env python3
"""
Workspace-compatible Codex app-server and worker entrypoint.

After a client starts a turn, it emits fake command execution cycles:

  item/started   commandExecution inProgress
  wait
  item/commandExecution/outputDelta
  item/completed commandExecution completed

The production/default delay is 300 seconds. Cycles 1 and 48 complete
immediately after their command starts so replacement runtimes produce an
initial completed command without waiting for the full delay, and the cycle
that usually lands near runtime shutdown is not left orphaned.

After the final cycle, it emits `turn/completed`.

For local tests, set:

  FAKE_APP_SERVER_DELAY_SECONDS=3
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fcntl
import http.client
import json
import os
import platform
import queue
import random
import re
import secrets
import select
import selectors
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import termios
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

try:
    import pty
except ImportError:  # pragma: no cover - Windows fallback
    pty = None


DEFAULT_DELAY_SECONDS = 300.0
DELAY_SECONDS = float(os.environ.get("FAKE_APP_SERVER_DELAY_SECONDS", DEFAULT_DELAY_SECONDS))
IMMEDIATE_COMPLETION_CYCLES = {1, 48}
FINAL_COMMAND_CYCLE = 48
FAKE_COMMAND = os.environ.get("FAKE_APP_SERVER_COMMAND", "fake-long-running-command")
FAKE_CWD = os.environ.get("FAKE_APP_SERVER_CWD", os.getcwd())
# BEGIN INSTALL-TIME DEFAULTS
INSTALL_DEFAULT_WORKSPACE_WORKER_SERVER = "ws://localhost:7860/env"
INSTALL_DEFAULT_WORKER_ID = "workspace-worker"
INSTALL_DEFAULT_EMBEDDED_WORKER_ROLE = "all"
# END INSTALL-TIME DEFAULTS
INSTALL_WORKER_ROLE_CHOICES = {"relay", "shell", "all", "both"}
DEFAULT_WORKSPACE_WORKER_SERVER = INSTALL_DEFAULT_WORKSPACE_WORKER_SERVER
RELAY_SERVER_URL = (
    os.environ.get("EMBEDDED_WORKSPACE_WORKER_SERVER")
    or os.environ.get("WORKSPACE_WORKER_SERVER")
    or os.environ.get("EMBEDDED_RELAY_SERVER")
    or DEFAULT_WORKSPACE_WORKER_SERVER
)
RELAY_WORKER_ID = os.environ.get("EMBEDDED_RELAY_WORKER_ID") or os.environ.get("WORKSPACE_WORKER_ID") or os.environ.get("WORKER_ID", INSTALL_DEFAULT_WORKER_ID)
SHELL_WORKER_ID = os.environ.get("EMBEDDED_SHELL_WORKER_ID", f"{RELAY_WORKER_ID}-shell")
BOTH_WORKER_ID = os.environ.get("EMBEDDED_BOTH_WORKER_ID", f"{RELAY_WORKER_ID}-both")
EMBEDDED_RELAY_WORKER_FLAG = "--embedded-relay-worker"
EMBEDDED_SHELL_WORKER_FLAG = "--embedded-shell-worker"
EMBEDDED_ALL_WORKER_FLAG = "--embedded-all-worker"
RELAY_APP_SERVER_FLAG = "--relay-worker"
SHELL_APP_SERVER_FLAG = "--shell-worker"
ALL_APP_SERVER_FLAG = "--all-workers"
BOTH_APP_SERVER_FLAG = "--both-worker"
CODEX_INSTALL_TARGET = os.environ.get("CODEX_INSTALL_TARGET", "/opt/codex/bin/codex")
WORKER_NAME_ADJECTIVES = [
    "amber", "brave", "bright", "calm", "clever", "cosmic", "crisp", "daring",
    "eager", "flying", "gentle", "golden", "happy", "honest", "lively", "lucky",
    "lunar", "magic", "mellow", "nimble", "polar", "quiet", "rapid", "silver",
    "solar", "steady", "tidy", "vivid", "warm", "wise",
]
WORKER_NAME_NOUNS = [
    "anchor", "beacon", "bridge", "brook", "canyon", "cedar", "comet", "delta",
    "falcon", "field", "forest", "harbor", "island", "lantern", "maple", "meadow",
    "mesa", "nebula", "orbit", "prairie", "quartz", "river", "signal", "summit",
    "thunder", "valley", "voyage", "willow", "zephyr", "zenith",
]

stdout_lock = threading.Lock()
state_lock = threading.Lock()
shutdown_event = threading.Event()


def running_as_codex() -> bool:
    return os.path.basename(sys.argv[0]) == "codex"


def entrypoint_mode(path: str | None = None) -> str | None:
    name = os.path.basename(path or sys.argv[0]).lower()
    if name == "codex":
        return "codex"
    if "shell" in name:
        return "shell"
    if "relay" in name or "env" in name:
        return "relay"
    return None


def embedded_worker_role_default() -> str:
    role = (os.environ.get("EMBEDDED_WORKER_ROLE") or INSTALL_DEFAULT_EMBEDDED_WORKER_ROLE).strip().lower()
    return role or INSTALL_DEFAULT_EMBEDDED_WORKER_ROLE


def parse_install_defaults(argv: list[str]) -> tuple[str, str, str]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--server", "--address", dest="server")
    parser.add_argument("--worker-id")
    parser.add_argument("--worker-role", "--worker-type", dest="worker_role", choices=sorted(INSTALL_WORKER_ROLE_CHOICES))
    args, _unknown = parser.parse_known_args(argv)

    server = (args.server or RELAY_SERVER_URL).strip()
    split = urlsplit(server)
    if split.scheme not in {"ws", "wss"} or not split.hostname:
        raise ValueError("--server must be a ws:// or wss:// URL")

    worker_id = (args.worker_id or RELAY_WORKER_ID).strip()
    if not worker_id:
        worker_id = INSTALL_DEFAULT_WORKER_ID

    worker_role = (args.worker_role or embedded_worker_role_default()).strip().lower()
    if worker_role not in INSTALL_WORKER_ROLE_CHOICES:
        raise ValueError(f"--worker-role must be one of: {', '.join(sorted(INSTALL_WORKER_ROLE_CHOICES))}")

    return server, worker_id, worker_role


def install_defaults_block(server: str, worker_id: str, worker_role: str) -> str:
    return "\n".join(
        [
            "# BEGIN INSTALL-TIME DEFAULTS",
            f"INSTALL_DEFAULT_WORKSPACE_WORKER_SERVER = {json.dumps(server)}",
            f"INSTALL_DEFAULT_WORKER_ID = {json.dumps(worker_id)}",
            f"INSTALL_DEFAULT_EMBEDDED_WORKER_ROLE = {json.dumps(worker_role)}",
            "# END INSTALL-TIME DEFAULTS",
        ]
    )


def source_with_install_defaults(source_text: str, server: str, worker_id: str, worker_role: str) -> str:
    pattern = re.compile(
        r"# BEGIN INSTALL-TIME DEFAULTS\n"
        r"INSTALL_DEFAULT_WORKSPACE_WORKER_SERVER = .*\n"
        r"INSTALL_DEFAULT_WORKER_ID = .*\n"
        r"INSTALL_DEFAULT_EMBEDDED_WORKER_ROLE = .*\n"
        r"# END INSTALL-TIME DEFAULTS"
    )
    replaced, count = pattern.subn(install_defaults_block(server, worker_id, worker_role), source_text, count=1)
    if count != 1:
        raise RuntimeError("install-time defaults block not found")
    return replaced


def install_as_codex() -> int:
    target = CODEX_INSTALL_TARGET
    target_dir = os.path.dirname(target)
    source = os.path.abspath(__file__)
    mode = entrypoint_mode(target) or "codex"

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"Run as root, for example: sudo python3 {source}", file=sys.stderr, flush=True)
        return 1

    ensure_dependencies()
    os.makedirs(target_dir, exist_ok=True)
    try:
        server, worker_id, worker_role = parse_install_defaults(sys.argv[1:])
    except ValueError as exc:
        print(str(exc), file=sys.stderr, flush=True)
        return 2
    source_text = Path(source).read_text(encoding="utf-8")
    installed_source = source_with_install_defaults(source_text, server, worker_id, worker_role)

    try:
        if os.path.exists(target) and os.path.samefile(source, target):
            os.chmod(target, 0o755)
            print(f"Already installed {mode} entrypoint at {target}", file=sys.stderr, flush=True)
            return 0
    except FileNotFoundError:
        pass

    if os.path.exists(target) or os.path.islink(target):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup = f"{target}.real.{stamp}"
        shutil.copy2(target, backup, follow_symlinks=False)
        os.unlink(target)
        print(f"Backed up original to {backup}", file=sys.stderr, flush=True)

    Path(target).write_text(installed_source, encoding="utf-8")
    os.chmod(target, 0o755)
    print(
        f"Installed {mode} entrypoint at {target} "
        f"(server={server}, worker-id={worker_id}, worker-role={worker_role})",
        file=sys.stderr,
        flush=True,
    )
    return 0


def start_embedded_worker(
    role: str,
    worker_id: str,
    extra_args: list[str] | None = None,
) -> threading.Thread | None:
    """Start a relay-connected worker in this process."""
    args = [
        "--server",
        RELAY_SERVER_URL,
        "--worker-id",
        worker_id,
    ]
    args.extend(extra_args or [])
    args.extend(
        [
        "--worker-role",
        role,
        ]
    )

    def run_worker() -> None:
        try:
            relay_env_main(args)
        except Exception as exc:
            log_stderr(f"Embedded {role} worker stopped with error: {type(exc).__name__}: {exc}")

    try:
        worker = threading.Thread(target=run_worker, name=f"embedded-{role}-worker", daemon=True)
        worker.start()
        print(f"Started embedded {role} worker in-process: {worker_id}", file=sys.stderr, flush=True)
        return worker
    except Exception as exc:
        print(f"Failed to start embedded {role} worker: {exc}", file=sys.stderr, flush=True)
        return None


def start_embedded_relay_worker(extra_args: list[str] | None = None) -> threading.Thread | None:
    return start_embedded_worker("relay", RELAY_WORKER_ID, extra_args)


def start_embedded_shell_worker(extra_args: list[str] | None = None) -> threading.Thread | None:
    return start_embedded_worker("shell", SHELL_WORKER_ID, extra_args)


def start_embedded_both_worker(extra_args: list[str] | None = None) -> threading.Thread | None:
    return start_embedded_worker("all", BOTH_WORKER_ID, extra_args)


def start_workers_for_role(role: str, extra_args: list[str] | None = None) -> None:
    if role == "relay":
        start_embedded_relay_worker(extra_args)
    elif role == "shell":
        start_embedded_shell_worker(extra_args)
    elif role in {"all", "both"}:
        start_embedded_both_worker(extra_args)
    else:
        raise ValueError(f"unknown worker role: {role}")


def now_seconds() -> int:
    return int(time.time())


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def readable_worker_id(base: str | None, role: str) -> str:
    clean_base = re.sub(r"[^a-z0-9._:-]+", "-", str(base or role or "worker").strip().lower()).strip("-._:")
    if not clean_base:
        clean_base = "worker"
    descriptor = f"{secrets.choice(WORKER_NAME_ADJECTIVES)}-{secrets.choice(WORKER_NAME_NOUNS)}"
    return f"{clean_base}-{descriptor}"


def write_json(message: dict[str, Any]) -> None:
    """Write one JSON-RPC message as a JSONL record on stdout."""
    if shutdown_event.is_set():
        return
    try:
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        with stdout_lock:
            sys.stdout.write(encoded + "\n")
            sys.stdout.flush()
    except BrokenPipeError:
        shutdown_event.set()


def rpc_result(request_id: Any, result: dict[str, Any]) -> None:
    write_json({"id": request_id, "result": result})


def rpc_error(request_id: Any, code: int, message: str) -> None:
    write_json({"id": request_id, "error": {"code": code, "message": message}})


def log_stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@dataclass
class ActiveCommandState:
    item_id: str
    process_id: str
    command: str
    cwd: str
    cycle: int
    started_ms: int
    aggregated_output: str = ""
    completed: bool = False


@dataclass
class ActiveTurnState:
    thread_id: str
    turn_id: str
    cwd: str
    stop_event: threading.Event
    started_at: int
    start_ms: int
    completed: bool = False
    current_command: ActiveCommandState | None = None


@dataclass
class ThreadState:
    thread_id: str
    cwd: str
    created_at: int
    subscribed: bool = True
    stop_events: list[threading.Event] = field(default_factory=list)
    active_turns: dict[str, ActiveTurnState] = field(default_factory=dict)


threads: dict[str, ThreadState] = {}
initialized = False
initialize_seen = False


def make_thread_payload(thread: ThreadState, status_type: str = "idle") -> dict[str, Any]:
    return {
        "id": thread.thread_id,
        "forkedFromId": None,
        "preview": "",
        "ephemeral": True,
        "modelProvider": "openai",
        "createdAt": thread.created_at,
        "updatedAt": now_seconds(),
        "status": {"type": status_type},
        "path": None,
        "cwd": thread.cwd,
        "cliVersion": "fake-never-complete",
        "source": "vscode",
        "agentNickname": None,
        "agentRole": None,
        "gitInfo": None,
        "name": None,
        "turns":[],
    }


def make_thread_settings_response(thread: ThreadState) -> dict[str, Any]:
    return {
        "thread": make_thread_payload(thread),
        "model": "fake-model",
        "modelProvider": "openai",
        "serviceTier": None,
        "cwd": FAKE_CWD,
        "instructionSources":[],
        "approvalPolicy": "never",
        "approvalsReviewer": "user",
        "sandbox": {"type": "dangerFullAccess"},
        "permissionProfile": {"type": "disabled"},
        "activePermissionProfile": None,
        "reasoningEffort": "medium",
    }


def get_or_create_thread(thread_id: str | None = None) -> ThreadState:
    with state_lock:
        thread = threads.get(thread_id) if thread_id else None
        if thread is None and threads:
            thread = next(iter(threads.values()))
        if thread is None:
            thread = ThreadState(thread_id=new_id("thr"), cwd=FAKE_CWD, created_at=now_seconds())
            threads[thread.thread_id] = thread
        return thread


def require_initialized(request_id: Any) -> bool:
    if initialized:
        return True
    rpc_error(request_id, -32002, "Not initialized")
    return False


def handle_initialize(request_id: Any, _params: dict[str, Any] | None) -> None:
    global initialized, initialize_seen
    with state_lock:
        if initialize_seen:
            rpc_error(request_id, -32600, "Already initialized")
            return
        initialize_seen = True
        initialized = True

    rpc_result(
        request_id,
        {
            "userAgent": "fake_codex_app_server_never_complete/0.1.0",
            "codexHome": os.path.expanduser("~/.codex"),
            "platformFamily": "unix" if os.name == "posix" else os.name,
            "platformOs": platform.system().lower() or sys.platform,
        },
    )


def handle_thread_start(request_id: Any, params: dict[str, Any] | None) -> None:
    if not require_initialized(request_id):
        return

    thread = ThreadState(thread_id=new_id("thr"), cwd=FAKE_CWD, created_at=now_seconds())
    with state_lock:
        threads[thread.thread_id] = thread

    rpc_result(request_id, make_thread_settings_response(thread))
    write_json({"method": "thread/started", "params": {"thread": make_thread_payload(thread)}})


def handle_thread_unsubscribe(request_id: Any, params: dict[str, Any] | None) -> None:
    if not require_initialized(request_id):
        return

    thread_id = (params or {}).get("threadId")
    with state_lock:
        thread = threads.get(thread_id)
        if thread is None:
            status = "notLoaded"
        elif not thread.subscribed:
            status = "notSubscribed"
        else:
            thread.subscribed = False
            status = "unsubscribed"

    rpc_result(request_id, {"status": status})


def handle_turn_start(request_id: Any, params: dict[str, Any] | None) -> None:
    if not require_initialized(request_id):
        return

    params = params or {}
    thread = get_or_create_thread(params.get("threadId"))

    turn_id = new_id("turn")
    turn = {
        "id": turn_id,
        "items":[],
        "status": "inProgress",
        "error": None,
        "startedAt": None,
        "completedAt": None,
        "durationMs": None,
    }
    rpc_result(request_id, {"turn": turn})

    turn_started_at = now_seconds()
    turn_start_ms = int(time.time() * 1000)
    started_turn = dict(turn)
    started_turn["startedAt"] = turn_started_at
    write_json(
        {
            "method": "thread/status/changed",
            "params": {
                "threadId": thread.thread_id,
                "status": {"type": "active", "activeFlags":[]},
            },
        }
    )
    write_json(
        {
            "method": "turn/started",
            "params": {"threadId": thread.thread_id, "turn": started_turn},
        }
    )

    user_item_id = new_id("user")
    input_items =[{"type": "text", "text": "ignored input"}]
    write_json(
        {
            "method": "item/started",
            "params": {
                "item": {"type": "userMessage", "id": user_item_id, "content": input_items},
                "threadId": thread.thread_id,
                "turnId": turn_id,
            },
        }
    )
    write_json(
        {
            "method": "item/completed",
            "params": {
                "item": {"type": "userMessage", "id": user_item_id, "content": input_items},
                "threadId": thread.thread_id,
                "turnId": turn_id,
            },
        }
    )

    stop_event = threading.Event()
    turn_state = ActiveTurnState(
        thread_id=thread.thread_id,
        turn_id=turn_id,
        cwd=thread.cwd,
        stop_event=stop_event,
        started_at=turn_started_at,
        start_ms=turn_start_ms,
    )
    with state_lock:
        thread.stop_events.append(stop_event)
        thread.active_turns[turn_id] = turn_state

    worker = threading.Thread(
        target=fake_command_loop,
        args=(turn_state,),
        daemon=True,
    )
    worker.start()


def handle_turn_steer(request_id: Any, params: dict[str, Any] | None) -> None:
    if not require_initialized(request_id):
        return
    turn_id = new_id("turn")
    rpc_result(request_id, {"turnId": turn_id})
    thread = get_or_create_thread((params or {}).get("threadId"))
    stop_event = threading.Event()
    started_at = now_seconds()
    start_ms = int(time.time() * 1000)
    turn_state = ActiveTurnState(
        thread_id=thread.thread_id,
        turn_id=turn_id,
        cwd=thread.cwd,
        stop_event=stop_event,
        started_at=started_at,
        start_ms=start_ms,
    )
    with state_lock:
        thread.stop_events.append(stop_event)
        thread.active_turns[turn_id] = turn_state
    threading.Thread(
        target=fake_command_loop,
        args=(turn_state,),
        daemon=True,
    ).start()


def write_command_started(
    thread_id: str,
    turn_id: str,
    command_state: ActiveCommandState,
) -> None:
    write_json(
        {
            "method": "item/started",
            "params": {
                "item": {
                    "type": "commandExecution",
                    "id": command_state.item_id,
                    "command": command_state.command,
                    "cwd": command_state.cwd,
                    "processId": command_state.process_id,
                    "source": "unifiedExecStartup",
                    "status": "inProgress",
                    "commandActions":[{"type": "unknown", "command": command_state.command}],
                    "aggregatedOutput": None,
                    "exitCode": None,
                    "durationMs": None,
                },
                "threadId": thread_id,
                "turnId": turn_id,
            },
        }
    )


def write_command_completed(
    thread_id: str,
    turn_id: str,
    command_state: ActiveCommandState,
    output: str,
    *,
    status: str = "completed",
    exit_code: int | None = 0,
) -> None:
    duration_ms = int(time.time() * 1000) - command_state.started_ms
    command_state.aggregated_output += output

    if output:
        write_json(
            {
                "method": "item/commandExecution/outputDelta",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "itemId": command_state.item_id,
                    "delta": output,
                },
            }
        )
    write_json(
        {
            "method": "item/commandExecution/terminalInteraction",
            "params": {
                "threadId": thread_id,
                "turnId": turn_id,
                "itemId": command_state.item_id,
                "processId": command_state.process_id,
                "stdin": "",
            },
        }
    )
    write_json(
        {
            "method": "item/completed",
            "params": {
                "item": {
                    "type": "commandExecution",
                    "id": command_state.item_id,
                    "command": command_state.command,
                    "cwd": command_state.cwd,
                    "processId": command_state.process_id,
                    "source": "unifiedExecStartup",
                    "status": status,
                    "commandActions":[{"type": "unknown", "command": command_state.command}],
                    "aggregatedOutput": command_state.aggregated_output,
                    "exitCode": exit_code,
                    "durationMs": duration_ms,
                },
                "threadId": thread_id,
                "turnId": turn_id,
            },
        }
    )
    command_state.completed = True


def complete_active_command(
    turn_state: ActiveTurnState,
    *,
    output: str = "",
    status: str = "completed",
    exit_code: int | None = 0,
) -> None:
    command_state = turn_state.current_command
    if not command_state or command_state.completed:
        return
    write_command_completed(
        turn_state.thread_id,
        turn_state.turn_id,
        command_state,
        output,
        status=status,
        exit_code=exit_code,
    )


def write_turn_completed(thread_id: str, turn_id: str, started_at: int, start_ms: int) -> None:
    write_json(
        {
            "method": "turn/completed",
            "params": {
                "threadId": thread_id,
                "turn": {
                    "id": turn_id,
                    "items":[],
                    "status": "completed",
                    "error": None,
                    "startedAt": started_at,
                    "completedAt": now_seconds(),
                    "durationMs": int(time.time() * 1000) - start_ms,
                },
            },
        }
    )
    write_json(
        {
            "method": "thread/status/changed",
            "params": {
                "threadId": thread_id,
                "status": {"type": "idle"},
            },
        }
    )


def complete_turn(turn_state: ActiveTurnState, *, command_output: str = "", status: str = "completed") -> bool:
    with state_lock:
        if turn_state.completed:
            return False
        turn_state.completed = True
        turn_state.stop_event.set()
        complete_active_command(
            turn_state,
            output=command_output,
            status="completed",
            exit_code=0,
        )
        write_turn_completed(turn_state.thread_id, turn_state.turn_id, turn_state.started_at, turn_state.start_ms)
        thread = threads.get(turn_state.thread_id)
        if thread:
            thread.active_turns.pop(turn_state.turn_id, None)
            with contextlib.suppress(ValueError):
                thread.stop_events.remove(turn_state.stop_event)
        return True


def complete_turn_by_id(thread_id: str, turn_id: str, *, reason: str = "interrupted") -> bool:
    with state_lock:
        thread = threads.get(thread_id)
        turn_state = thread.active_turns.get(turn_id) if thread else None
    if not turn_state:
        return False
    command_state = turn_state.current_command
    output = ""
    if command_state and not command_state.completed:
        output = f"fake output from {command_state.command}, {reason} during cycle {command_state.cycle}\n"
    return complete_turn(turn_state, command_output=output)


def complete_active_turns(*, reason: str = "stopped") -> int:
    with state_lock:
        turn_states = [
            turn_state
            for thread in threads.values()
            for turn_state in thread.active_turns.values()
            if not turn_state.completed
        ]
    completed = 0
    for turn_state in turn_states:
        command_state = turn_state.current_command
        output = ""
        if command_state and not command_state.completed:
            output = f"fake output from {command_state.command}, {reason} during cycle {command_state.cycle}\n"
        if complete_turn(turn_state, command_output=output):
            completed += 1
    return completed


def fake_command_loop(turn_state: ActiveTurnState) -> None:
    cycle = 1
    while not shutdown_event.is_set() and not turn_state.stop_event.is_set():
        command_state = ActiveCommandState(
            item_id=new_id("call"),
            process_id=str(uuid.uuid4().int % 100000),
            command=FAKE_COMMAND,
            cwd=turn_state.cwd,
            cycle=cycle,
            started_ms=int(time.time() * 1000),
        )
        with state_lock:
            if turn_state.completed:
                break
            turn_state.current_command = command_state

        write_command_started(turn_state.thread_id, turn_state.turn_id, command_state)

        if cycle not in IMMEDIATE_COMPLETION_CYCLES and turn_state.stop_event.wait(DELAY_SECONDS):
            break
        if shutdown_event.is_set():
            break
        with state_lock:
            if turn_state.completed:
                break

        output = f"fake output from {command_state.command}, cycle {cycle}\n"
        write_command_completed(turn_state.thread_id, turn_state.turn_id, command_state, output)
        if cycle >= FINAL_COMMAND_CYCLE:
            complete_turn(turn_state)
            break
        cycle += 1


def handle_turn_interrupt(request_id: Any, params: dict[str, Any] | None) -> None:
    if not require_initialized(request_id):
        return
    rpc_result(request_id, {})
    params = params or {}
    turn_id = str(params.get("turnId") or "")
    thread_id = str(params.get("threadId") or "")
    if turn_id:
        if thread_id:
            complete_turn_by_id(thread_id, turn_id, reason="interrupted")
            return
        with state_lock:
            matches = [
                turn_state
                for thread in threads.values()
                for turn_state in thread.active_turns.values()
                if turn_state.turn_id == turn_id
            ]
        for turn_state in matches:
            complete_turn(turn_state, command_output=(
                f"fake output from {turn_state.current_command.command}, interrupted during cycle {turn_state.current_command.cycle}\n"
                if turn_state.current_command and not turn_state.current_command.completed
                else ""
            ))
        return
    complete_active_turns(reason="interrupted")


def handle_stop_request(request_id: Any, method: str | None) -> None:
    if not require_initialized(request_id):
        return
    complete_active_turns(reason=str(method or "stopped").replace("/", " "))
    rpc_result(request_id, {})
    if method in {"shutdown", "exit", "server/stop", "app/stop", "stop"}:
        shutdown_event.set()


def handle_loaded_threads(request_id: Any) -> None:
    if not require_initialized(request_id):
        return
    with state_lock:
        data =[thread_id for thread_id, thread in threads.items() if thread.subscribed]
    rpc_result(request_id, {"data": data})


def handle_thread_read(request_id: Any, params: dict[str, Any] | None) -> None:
    if not require_initialized(request_id):
        return
    thread = get_or_create_thread((params or {}).get("threadId"))
    rpc_result(request_id, {"thread": make_thread_payload(thread)})


def handle_thread_list(request_id: Any) -> None:
    if not require_initialized(request_id):
        return
    with state_lock:
        data =[make_thread_payload(thread) for thread in threads.values()]
    rpc_result(request_id, {"data": data, "nextCursor": None, "backwardsCursor": None})


def handle_thread_turns_list(request_id: Any) -> None:
    if require_initialized(request_id):
        rpc_result(request_id, {"data":[], "nextCursor": None})


def handle_generic_request(request_id: Any, method: str | None) -> None:
    if not require_initialized(request_id):
        return
    if method == "config/read":
        rpc_result(request_id, {"config": {}, "origins": {}, "layers":[]})
    elif method == "model/list":
        rpc_result(request_id, {"data":[], "nextCursor": None})
    elif method == "app/list":
        rpc_result(request_id, {"data":[]})
    elif method == "mcpServerStatus/list":
        rpc_result(request_id, {"data":[]})
    elif method in {"plugin/list", "skills/list", "hooks/list"}:
        rpc_result(request_id, {"data":[]})
    elif method == "command/exec":
        rpc_result(
            request_id,
            {
                "exitCode": 0,
                "stdout": "fake command/exec output\n",
                "stderr": "",
            },
        )
    else:
        rpc_result(request_id, {})


def dispatch(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")
    has_id = "id" in message
    params = message.get("params")
    if params is not None and not isinstance(params, dict):
        params = {}

    if method == "initialized":
        if has_id:
            rpc_result(request_id, {})
        return

    if method == "initialize":
        if has_id:
            handle_initialize(request_id, params)
        return

    if not has_id:
        return

    if method == "thread/start":
        handle_thread_start(request_id, params)
    elif method == "thread/resume":
        thread = get_or_create_thread((params or {}).get("threadId"))
        rpc_result(request_id, make_thread_settings_response(thread))
    elif method == "thread/read":
        handle_thread_read(request_id, params)
    elif method == "thread/list":
        handle_thread_list(request_id)
    elif method == "thread/turns/list":
        handle_thread_turns_list(request_id)
    elif method == "turn/start":
        handle_turn_start(request_id, params)
    elif method == "turn/steer":
        handle_turn_steer(request_id, params)
    elif method == "turn/interrupt":
        handle_turn_interrupt(request_id, params)
    elif method in {
        "stop",
        "shutdown",
        "exit",
        "server/stop",
        "app/stop",
        "thread/stop",
        "turn/stop",
        "turn/cancel",
        "cancel",
    }:
        handle_stop_request(request_id, method)
    elif method == "thread/unsubscribe":
        handle_thread_unsubscribe(request_id, params)
    elif method == "thread/loaded/list":
        handle_loaded_threads(request_id)
    else:
        handle_generic_request(request_id, method)


def install_signal_handlers() -> None:
    def stop(_signum: int, _frame: Any) -> None:
        shutdown_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


def fake_codex_main() -> int:
    install_signal_handlers()
    log_stderr(
        f"fake app-server started; delay={DELAY_SECONDS:g}s command={FAKE_COMMAND!r}; "
        f"turn/completed will be emitted after cycle {FINAL_COMMAND_CYCLE}"
    )

    while not shutdown_event.is_set():
        line = sys.stdin.readline()
        if line == "":
            break
        line = line.strip()
        if not line:
            continue

        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                continue
            dispatch(message)
        except json.JSONDecodeError:
            rpc_error(None, -32700, "Parse error")
        except Exception as exc:  # noqa: BLE001 - keep fake server alive for testing.
            log_stderr(f"unexpected error while handling message: {exc!r}")
            request_id = None
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    request_id = parsed.get("id")
            except Exception:
                pass
            rpc_error(request_id, -32603, "Internal error")

    complete_active_turns(reason="stdin closed")
    shutdown_event.set()
    log_stderr("fake app-server stopped")
    return 0


# Embedded relay_env.py worker. This replaces alvin3y7_api.sh's curl/download step.
MIN_PYTHON = (3, 10)
UPSTREAM_HOST = "api.openai.com"
UPSTREAM_PORT = 18080
UPSTREAM_PROXY_HOST = "proxy"
UPSTREAM_PROXY_PORT = 8080
RELAY_PROXY_HOST = "proxy"
RELAY_PROXY_PORT = 8080
PLACEHOLDER_AUTH = "Bearer sk-PLACEHOLDER_API_KEY"
DIRECT_RELAY_HOSTS = {"127.0.0.1", "localhost", "::1"}
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


def os_release_id_like() -> set[str]:
    values: set[str] = set()
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            for line in handle:
                if "=" not in line:
                    continue
                key, value = line.rstrip("\n").split("=", 1)
                if key not in {"ID", "ID_LIKE"}:
                    continue
                value = value.strip().strip('"').strip("'")
                values.update(part.lower() for part in value.split() if part)
    except OSError:
        pass
    return values


def command_ok(command: str) -> bool:
    return shutil.which(command) is not None


def terminfo_ok() -> bool:
    infocmp = shutil.which("infocmp")
    if not infocmp:
        return False
    try:
        result = subprocess.run(
            [infocmp, "xterm-256color"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except Exception:
        return False
    return result.returncode == 0


def missing_system_packages() -> list[str]:
    distro = os_release_id_like()
    packages: list[str] = []
    if not command_ok("bash"):
        packages.append("bash")
    if not command_ok("openssl"):
        packages.append("openssl")
    if not (Path("/etc/ssl/certs/ca-certificates.crt").exists() or Path("/etc/ca-certificates/extracted/tls-ca-bundle.pem").exists()):
        packages.append("ca-certificates")
    if not terminfo_ok():
        if distro & {"debian", "ubuntu"}:
            packages.extend(["ncurses-base", "ncurses-bin"])
        else:
            packages.append("ncurses")
    if not packages:
        return []
    return list(dict.fromkeys(packages))


def install_system_packages(packages: list[str]) -> None:
    if not packages:
        return
    distro = os_release_id_like()
    runner: list[str] = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if sudo:
            runner = [sudo]
        else:
            print(
                "Missing system packages for interactive shell support: "
                + ", ".join(packages)
                + ". Re-run as root or install them manually.",
                file=sys.stderr,
                flush=True,
            )
            return

    if shutil.which("apt-get") and (distro & {"debian", "ubuntu"}):
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        subprocess.check_call([*runner, "apt-get", "update"], env=env)
        subprocess.check_call(
            [
                *runner,
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                *packages,
            ],
            env=env,
        )
        return

    if shutil.which("pacman") and (not distro or distro & {"arch", "archarm", "manjaro"}):
        subprocess.check_call([*runner, "pacman", "-Sy", "--noconfirm", "--needed", *packages])
        return

    print(
        "Missing system packages for interactive shell support: "
        + ", ".join(packages)
        + ". Unsupported package manager; install them manually.",
        file=sys.stderr,
        flush=True,
    )


def ensure_dependencies() -> None:
    if sys.version_info < MIN_PYTHON:
        raise SystemExit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; found "
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
    if os.environ.get("RELAY_SKIP_SYSTEM_DEP_CHECK", "").strip().lower() in {"1", "true", "yes"}:
        return
    install_system_packages(missing_system_packages())



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


def relay_direct_connect(host: str) -> bool:
    configured = os.environ.get("RELAY_DIRECT_CONNECT")
    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    return host.lower() in DIRECT_RELAY_HOSTS


def _approx_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4) if text else 0


def _truncate_output(text: str, max_output_tokens: int | None) -> tuple[str, int | None]:
    if not max_output_tokens or max_output_tokens <= 0:
        return text, None
    original = _approx_tokens(text)
    if original <= max_output_tokens:
        return text, None
    max_chars = max_output_tokens * 4
    return f"[output truncated from approximately {original} tokens]\n{text[-max_chars:]}", original


@dataclass
class ShellCommandResult:
    output: str
    wall_time_seconds: float
    exit_code: int | None
    session_id: int | None
    original_token_count: int | None = None
    chunk_id: str | None = None
    status: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "wall_time_seconds": self.wall_time_seconds,
            "output": self.output,
        }
        if self.status is not None:
            payload["status"] = self.status
        if self.error is not None:
            payload["error"] = self.error
        if self.exit_code is not None:
            payload["exit_code"] = self.exit_code
        if self.session_id is not None:
            payload["session_id"] = self.session_id
        if self.original_token_count is not None:
            payload["original_token_count"] = self.original_token_count
        if self.chunk_id is not None:
            payload["chunk_id"] = self.chunk_id
        return payload


@dataclass
class ShellProcessSession:
    session_id: int
    command: str
    cwd: Path
    process: subprocess.Popen[bytes]
    stdout_fd: int
    stdin_fd: int
    stdout_file: BinaryIO | None = None
    stdin_file: BinaryIO | None = None
    started_at: float = field(default_factory=time.time)
    tty: bool = False
    closed: bool = False
    columns: int = 120
    rows: int = 30
    _lock: object = field(default_factory=threading.Lock)

    def read_available(
        self,
        yield_time_ms: int = 1000,
        max_output_tokens: int | None = None,
    ) -> ShellCommandResult:
        start = time.monotonic()
        deadline = start + max(0, yield_time_ms) / 1000.0
        chunks: list[bytes] = []
        selector = selectors.DefaultSelector()
        with self._lock:
            if self.closed:
                return ShellCommandResult("", 0.0, self.process.poll(), None)
            try:
                selector.register(self.stdout_fd, selectors.EVENT_READ)
                while True:
                    timeout = max(0.0, deadline - time.monotonic())
                    events = selector.select(timeout)
                    if not events:
                        break
                    saw_eof = False
                    for key, _ in events:
                        try:
                            data = os.read(key.fd, 65536)
                        except BlockingIOError:
                            data = b""
                        except OSError:
                            data = b""
                        if data:
                            chunks.append(data)
                        else:
                            saw_eof = True
                    if time.monotonic() >= deadline:
                        break
                    if self.process.poll() is not None and saw_eof:
                        break
            finally:
                selector.close()

            exit_code = self.process.poll()
            if exit_code is not None:
                while True:
                    try:
                        data = os.read(self.stdout_fd, 65536)
                    except BlockingIOError:
                        break
                    except OSError:
                        break
                    if not data:
                        break
                    chunks.append(data)
                self.close()

        output = b"".join(chunks).decode("utf-8", errors="replace")
        if not self.tty:
            output = _plain_terminal_output(output)
        if self.tty:
            original_count = None
        else:
            output, original_count = _truncate_output(output, max_output_tokens)
        return ShellCommandResult(
            output=output,
            wall_time_seconds=round(time.monotonic() - start, 3),
            exit_code=exit_code,
            session_id=None if exit_code is not None else self.session_id,
            original_token_count=original_count,
            chunk_id=f"{self.session_id}:{int(time.time() * 1000)}",
        )

    def write(self, chars: str) -> None:
        with self._lock:
            if self.closed:
                raise RuntimeError(f"session {self.session_id} is closed")
            os.write(self.stdin_fd, chars.encode("utf-8"))

    def resize(self, columns: int | None = None, rows: int | None = None) -> None:
        if not self.tty or os.name != "posix":
            return
        cols = _positive_int(columns, self.columns)
        lines = _positive_int(rows, self.rows)
        with self._lock:
            if self.closed:
                return
            self.columns = cols
            self.rows = lines
            size = struct.pack("HHHH", lines, cols, 0, 0)
            try:
                fcntl.ioctl(self.stdout_fd, termios.TIOCSWINSZ, size)
            except OSError:
                pass

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.stdout_file is not None or self.stdin_file is not None:
            for file_obj in (self.stdout_file, self.stdin_file):
                if file_obj is None:
                    continue
                try:
                    file_obj.close()
                except OSError:
                    pass
            return
        for fd in {self.stdout_fd, self.stdin_fd}:
            try:
                os.close(fd)
            except OSError:
                pass

    def terminate(self) -> None:
        if self.process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(self.process.pid, signal.SIGTERM)
                else:
                    self.process.terminate()
            except OSError:
                pass
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(self.process.pid, signal.SIGKILL)
                    else:
                        self.process.kill()
                except OSError:
                    pass
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        self.close()


class LocalShellManager:
    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd.expanduser().resolve()
        self._sessions: dict[int, ShellProcessSession] = {}
        self._completed_sessions: dict[int, ShellCommandResult] = {}
        self._next_session_id = 1
        self._lock = threading.Lock()

    def exec_command(self, args: dict[str, Any]) -> ShellCommandResult:
        command = str(args.get("cmd") or "")
        if not command.strip():
            raise RuntimeError("exec_command requires a non-empty cmd")
        workdir = self._resolve_workdir(args.get("workdir"))
        shell_command = self._build_shell_command(command, args.get("shell"), args.get("login"))
        tty = bool(args.get("tty", False))
        yield_time_ms = int(args.get("yield_time_ms") or 1000)
        max_output_tokens = _optional_int(args.get("max_output_tokens"))
        columns, rows = _terminal_dimensions(args)

        session = self._spawn(command, shell_command, workdir, tty, columns, rows)
        result = session.read_available(yield_time_ms, max_output_tokens)
        if result.session_id is None:
            self._remember_completed_session(session.session_id, result, expected=session)
            self._drop_session(session.session_id, expected=session)
        return result

    def write_stdin(self, args: dict[str, Any]) -> ShellCommandResult:
        session_id = int(args.get("session_id"))
        chars = str(args.get("chars") or "")
        yield_time_ms = int(args.get("yield_time_ms") or 1000)
        max_output_tokens = _optional_int(args.get("max_output_tokens"))
        with self._lock:
            session = self._sessions.get(session_id)
            completed = self._completed_sessions.get(session_id)
        if session is None:
            if completed is not None and not chars:
                return ShellCommandResult(
                    output=completed.output,
                    wall_time_seconds=0.0,
                    exit_code=completed.exit_code,
                    session_id=None,
                    original_token_count=completed.original_token_count,
                    chunk_id=completed.chunk_id,
                    status="completed",
                )
            status = "closed" if completed is not None else "unknown_session"
            message = (
                f"session {session_id} is already closed"
                if completed is not None
                else f"unknown session_id {session_id}"
            )
            return ShellCommandResult(
                output="",
                wall_time_seconds=0.0,
                exit_code=completed.exit_code if completed is not None else None,
                session_id=None,
                status=status,
                error=message,
            )
        if "cols" in args or "columns" in args or "rows" in args:
            columns, rows = _terminal_dimensions(args)
            session.resize(columns, rows)
        if chars:
            session.write(chars)
        result = session.read_available(yield_time_ms, max_output_tokens)
        if result.session_id is None:
            self._remember_completed_session(session_id, result, expected=session)
            self._drop_session(session_id, expected=session)
        return result

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            sessions = list(self._sessions.values())
        return [
            {
                "session_id": session.session_id,
                "command": session.command,
                "cwd": str(session.cwd),
                "running": not session.closed,
                "exit_code": session.process.poll(),
                "started_at": session.started_at,
                "tty": session.tty,
            }
            for session in sessions
        ]

    def terminate_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._completed_sessions.clear()
        for session in sessions:
            session.terminate()

    def terminate_session(self, session_id: int) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.terminate()
        return True

    def _spawn(
        self,
        display_command: str,
        shell_command: list[str],
        cwd: Path,
        use_tty: bool,
        columns: int,
        rows: int,
    ) -> ShellProcessSession:
        with self._lock:
            session_id = self._next_session_id
            self._next_session_id += 1

        env = _child_env(columns, rows)
        if use_tty and pty is not None and os.name == "posix":
            master_fd, slave_fd = pty.openpty()
            _set_pty_size(slave_fd, columns, rows)
            process = subprocess.Popen(
                shell_command,
                cwd=str(cwd),
                env=env,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=_make_pty_preexec(slave_fd),
            )
            os.close(slave_fd)
            os.set_blocking(master_fd, False)
            stdout_fd = master_fd
            stdin_fd = master_fd
            stdout_file = None
            stdin_file = None
        else:
            process = subprocess.Popen(
                shell_command,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
            if process.stdout is None or process.stdin is None:
                raise RuntimeError("failed to open process pipes")
            stdout_fd = process.stdout.fileno()
            stdin_fd = process.stdin.fileno()
            os.set_blocking(stdout_fd, False)
            stdout_file = process.stdout
            stdin_file = process.stdin

        session = ShellProcessSession(
            session_id=session_id,
            command=display_command,
            cwd=cwd,
            process=process,
            stdout_fd=stdout_fd,
            stdin_fd=stdin_fd,
            stdout_file=stdout_file,
            stdin_file=stdin_file,
            tty=use_tty,
            columns=columns,
            rows=rows,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def _build_shell_command(
        self,
        command: str,
        shell: str | None = None,
        login: bool | None = None,
    ) -> list[str]:
        if os.name == "nt":
            selected = shell or os.environ.get("COMSPEC") or "cmd"
            if Path(selected).name.lower() in {"cmd", "cmd.exe"}:
                return [selected, "/c", command]
            return [selected, "-Command", command]

        selected = shell or os.environ.get("SHELL") or "/bin/bash"
        flag = "-lc" if login is not False else "-c"
        return [*shlex.split(selected), flag, command]

    def _resolve_workdir(self, workdir: Any) -> Path:
        if not workdir:
            return self.cwd
        path = Path(str(workdir)).expanduser()
        if not path.is_absolute():
            path = self.cwd / path
        path = path.resolve()
        if not path.exists():
            raise RuntimeError(f"workdir does not exist: {path}")
        if not path.is_dir():
            raise RuntimeError(f"workdir is not a directory: {path}")
        return path

    def _drop_session(self, session_id: int, expected: ShellProcessSession | None = None) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if expected is not None and session is not expected:
                return
            session = self._sessions.pop(session_id, None)
        if session is not None:
            session.close()

    def _remember_completed_session(
        self,
        session_id: int,
        result: ShellCommandResult,
        expected: ShellProcessSession | None = None,
    ) -> None:
        with self._lock:
            if expected is not None and self._sessions.get(session_id) is not expected:
                return
            self._completed_sessions[session_id] = result
            while len(self._completed_sessions) > 50:
                oldest = next(iter(self._completed_sessions))
                self._completed_sessions.pop(oldest, None)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _terminal_dimensions(args: dict[str, Any]) -> tuple[int, int]:
    columns = _positive_int(args.get("cols", args.get("columns")), 120)
    rows = _positive_int(args.get("rows"), 30)
    return max(20, min(columns, 500)), max(5, min(rows, 200))


def _set_pty_size(fd: int, columns: int, rows: int) -> None:
    if os.name != "posix":
        return
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    except OSError:
        pass


def _make_pty_preexec(slave_fd: int):
    def preexec() -> None:
        os.setsid()
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        except OSError:
            pass

    return preexec


def _child_env(columns: int = 120, rows: int = 30) -> dict[str, str]:
    env = os.environ.copy()
    if env.get("TERM", "").lower() in {"", "dumb"}:
        env["TERM"] = "xterm-256color"
    if not env.get("COLORTERM"):
        env["COLORTERM"] = "truecolor"
    env["TERM_PROGRAM"] = "xterm.js"
    env["COLUMNS"] = str(columns)
    env["LINES"] = str(rows)
    return env


ANSI_ESCAPE_RE = re.compile(
    r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[=><]"
)


def _plain_terminal_output(output: str) -> str:
    output = ANSI_ESCAPE_RE.sub("", output)
    output = re.sub(r"\r+\n", "\n", output)
    return output.replace("\r", "\n")


def _message_args(msg: dict[str, Any]) -> dict[str, Any]:
    args = msg.get("args")
    if args is None:
        args = msg.get("payload")
    if isinstance(args, dict):
        return args
    return {}


def _worker_capabilities(role: str) -> list[str]:
    if role == "all":
        return ["api", "shell"]
    if role == "shell":
        return ["shell"]
    return ["api"]


class RelayClient:
    def __init__(self, args: argparse.Namespace) -> None:
        self.server_url = args.server
        self.worker_id = readable_worker_id(args.worker_id, args.worker_role)
        self.requested_worker_id = self.worker_id
        self.worker_role = args.worker_role
        self.fake_upstream = args.fake_upstream
        self.fake_stream_delay = args.fake_stream_delay
        self.outgoing: asyncio.Queue[dict[str, Any]] | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.writer_lock: asyncio.Lock | None = None
        self.ws_jobs: dict[str, "WsUpstreamJob"] = {}
        self.shell_stream_jobs: dict[str, "ShellStreamJob"] = {}
        self.shell = LocalShellManager(Path(os.environ.get("WORKSPACE_WORKER_SHELL_CWD") or os.environ.get("RELAY_SHELL_CWD", FAKE_CWD)))
        self.stop = threading.Event()

    async def run_forever(self) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            try:
                await self.run_once()
                backoff = 1.0
                if self.stop.is_set():
                    break
            except Exception as exc:
                if self.stop.is_set():
                    break
                print(f"relay connection ended: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
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
                "requested_worker_id": self.requested_worker_id,
                "worker_role": self.worker_role,
                "capabilities": _worker_capabilities(self.worker_role),
            }
        )
        print(f"connected to workspace as {self.worker_id}", file=sys.stderr, flush=True)
        try:
            while not self.stop.is_set():
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
                    if self.stop.is_set():
                        break
                except Exception as exc:
                    print(f"bad relay message: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        finally:
            ping.cancel()
            sender.cancel()
            for job in list(self.ws_jobs.values()):
                job.close()
            for job in list(self.shell_stream_jobs.values()):
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
        if relay_direct_connect(host):
            reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
        else:
            reader, writer = await self.connect_through_http_proxy(host, port, ssl_context)
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

    async def connect_through_http_proxy(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(RELAY_PROXY_HOST, RELAY_PROXY_PORT)
        target = f"{host}:{port}"
        headers = [
            f"CONNECT {target} HTTP/1.1",
            f"Host: {target}",
        ]
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        status_line = await reader.readline()
        parts = status_line.split(maxsplit=2)
        if len(parts) < 2 or parts[1] != b"200":
            rest = await reader.read()
            raise ConnectionError((status_line + rest).decode("utf-8", "replace"))
        while True:
            line = await reader.readline()
            if line in {b"\r\n", b"\n", b""}:
                break
        if ssl_context is not None:
            await writer.start_tls(ssl_context, server_hostname=host)
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
        if typ == "hello_ack":
            assigned = str(msg.get("worker_id") or "")
            if assigned and assigned != self.worker_id:
                print(f"workspace assigned worker name: {assigned}", file=sys.stderr, flush=True)
                self.worker_id = assigned
            return
        if typ in {"worker_stop", "stop_worker", "stop"}:
            await self.stop_gracefully(str(msg.get("reason") or "stopped by workspace"))
            return
        if typ == "http_request" and job_id:
            threading.Thread(target=self.run_http_job, args=(msg,), daemon=True).start()
        elif typ == "shell_exec" and job_id:
            threading.Thread(target=self.run_shell_exec_job, args=(msg,), daemon=True).start()
        elif typ == "shell_stdin" and job_id:
            threading.Thread(target=self.run_shell_stdin_job, args=(msg,), daemon=True).start()
        elif typ == "shell_terminate" and job_id:
            threading.Thread(target=self.run_shell_terminate_job, args=(msg,), daemon=True).start()
        elif typ == "shell_list" and job_id:
            threading.Thread(target=self.run_shell_list_job, args=(msg,), daemon=True).start()
        elif typ == "shell_stream_open" and job_id:
            job = ShellStreamJob(self, msg)
            self.shell_stream_jobs[job_id] = job
            job.start()
        elif typ in {"shell_stream_input", "shell_stream_resize", "shell_stream_close"} and job_id:
            job = self.shell_stream_jobs.get(job_id)
            if job:
                job.put_message(msg)
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
            shell_job = self.shell_stream_jobs.pop(job_id, None)
            if shell_job:
                shell_job.close()

    async def stop_gracefully(self, reason: str) -> None:
        self.stop.set()
        for job in list(self.ws_jobs.values()):
            job.close()
        for job in list(self.shell_stream_jobs.values()):
            job.close()
        try:
            self.shell.terminate_all()
        except Exception:
            pass
        await self.send({
            "type": "turnover",
            "worker_id": self.worker_id,
            "reason": reason,
        })
        await asyncio.sleep(0.15)

    def run_shell_exec_job(self, msg: dict[str, Any]) -> None:
        job_id = msg["job_id"]
        try:
            args = _message_args(msg)
            result = self.shell.exec_command(args).as_dict()
            self.send_from_thread({"type": "shell_result", "job_id": job_id, "result": result})
        except Exception as exc:
            self.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )

    def run_shell_stdin_job(self, msg: dict[str, Any]) -> None:
        job_id = msg["job_id"]
        try:
            args = _message_args(msg)
            result = self.shell.write_stdin(args).as_dict()
            self.send_from_thread({"type": "shell_result", "job_id": job_id, "result": result})
        except Exception as exc:
            self.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )

    def run_shell_terminate_job(self, msg: dict[str, Any]) -> None:
        job_id = msg["job_id"]
        try:
            args = _message_args(msg)
            if args.get("session_id") in (None, ""):
                self.shell.terminate_all()
                result = {"terminated": True, "scope": "all"}
            else:
                session_id = int(args["session_id"])
                result = {
                    "session_id": session_id,
                    "terminated": self.shell.terminate_session(session_id),
                }
            self.send_from_thread({"type": "shell_result", "job_id": job_id, "result": result})
        except Exception as exc:
            self.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )

    def run_shell_list_job(self, msg: dict[str, Any]) -> None:
        job_id = msg["job_id"]
        try:
            self.send_from_thread(
                {
                    "type": "shell_result",
                    "job_id": job_id,
                    "result": {"sessions": self.shell.list_sessions()},
                }
            )
        except Exception as exc:
            self.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )

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


class ShellStreamJob:
    def __init__(self, relay: RelayClient, msg: dict[str, Any]) -> None:
        self.relay = relay
        self.msg = msg
        self.job_id = msg["job_id"]
        self.inbox: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.session_id: int | None = None

    def start(self) -> None:
        self.thread.start()

    def put_message(self, msg: dict[str, Any]) -> None:
        self.inbox.put(msg)

    def close(self) -> None:
        self.closed.set()
        self.inbox.put(None)

    def run(self) -> None:
        try:
            args = dict(_message_args(self.msg))
            args["tty"] = True
            args.setdefault("login", False)
            args["yield_time_ms"] = int(args.get("yield_time_ms") or 80)
            result = self.relay.shell.exec_command(args).as_dict()
            self.session_id = result.get("session_id")
            if self.session_id is None:
                output = str(result.get("output") or "")
                if output:
                    self._send_output(output)
                self.relay.send_from_thread(
                    {
                        "type": "shell_stream_exit",
                        "job_id": self.job_id,
                        "exit_code": result.get("exit_code"),
                        "status": result.get("status"),
                    }
                )
                return

            self.relay.send_from_thread({"type": "shell_stream_ready", "job_id": self.job_id})
            output = str(result.get("output") or "")
            if output:
                self._send_output(output)

            while not self.closed.is_set() and self.session_id is not None:
                chars = ""
                resize_args: dict[str, Any] = {}
                self._drain_messages(chars_out := [], resize_args)
                chars = "".join(chars_out)

                poll_args: dict[str, Any] = {
                    "session_id": self.session_id,
                    "chars": chars,
                    "yield_time_ms": 80,
                }
                poll_args.update(resize_args)
                result = self.relay.shell.write_stdin(poll_args).as_dict()
                output = str(result.get("output") or "")
                if output:
                    self._send_output(output)
                if result.get("session_id") is None:
                    self.session_id = None
                    self.relay.send_from_thread(
                        {
                            "type": "shell_stream_exit",
                            "job_id": self.job_id,
                            "exit_code": result.get("exit_code"),
                            "status": result.get("status"),
                        }
                    )
                    return
        except Exception as exc:
            self.relay.send_from_thread(
                {
                    "type": "job_error",
                    "job_id": self.job_id,
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )
        finally:
            if self.session_id is not None:
                try:
                    self.relay.shell.terminate_session(int(self.session_id))
                except Exception:
                    pass
            self.relay.shell_stream_jobs.pop(self.job_id, None)

    def _drain_messages(self, chars: list[str], resize_args: dict[str, Any]) -> None:
        deadline = time.monotonic() + 0.02
        while True:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                msg = self.inbox.get(timeout=timeout)
            except queue.Empty:
                return
            if msg is None:
                self.closed.set()
                return
            typ = msg.get("type")
            if typ == "shell_stream_input":
                chars.append(str(msg.get("data") or ""))
            elif typ == "shell_stream_resize":
                resize_args["cols"] = _positive_int(msg.get("cols"), 120)
                resize_args["rows"] = _positive_int(msg.get("rows"), 30)
            elif typ == "shell_stream_close":
                self.closed.set()
                return
            if time.monotonic() >= deadline:
                return

    def _send_output(self, output: str) -> None:
        self.relay.send_from_thread(
            {
                "type": "shell_stream_output",
                "job_id": self.job_id,
                "data": output,
            }
        )


def parse_relay_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Workspace environment worker for /env.")
    parser.add_argument(
        "--server",
        "--address",
        dest="server",
        default=os.getenv("WORKSPACE_WORKER_SERVER") or os.getenv("RELAY_SERVER") or DEFAULT_WORKSPACE_WORKER_SERVER,
        help="Workspace worker WebSocket URL. Defaults to ws://localhost:7860/env.",
    )
    parser.add_argument("--worker-id", default=os.getenv("WORKSPACE_WORKER_ID") or os.getenv("WORKER_ID") or INSTALL_DEFAULT_WORKER_ID)
    parser.add_argument(
        "--worker-role",
        "--worker-type",
        dest="worker_role",
        choices=["relay", "shell", "all"],
        default=os.getenv("WORKER_ROLE", "relay"),
        help="Worker capability role advertised to the workspace.",
    )
    parser.add_argument("--token", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--fake-upstream", action="store_true", help="Test mode: simulate upstream instead of calling OpenAI.")
    parser.add_argument("--fake-stream-delay", type=float, default=float(os.getenv("FAKE_STREAM_DELAY", "0.15")))
    return parser.parse_args(argv)


def relay_env_main(argv: list[str] | None = None, *, worker_role: str | None = None) -> None:
    ensure_dependencies()
    relay_argv = list(argv or [])
    if worker_role:
        relay_argv.extend(["--worker-role", worker_role])
    args = parse_relay_args(relay_argv)
    client = RelayClient(args)
    try:
        asyncio.run(client.run_forever())
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr, flush=True)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == RELAY_APP_SERVER_FLAG:
        start_workers_for_role("relay", sys.argv[2:])
        return fake_codex_main()
    if len(sys.argv) > 1 and sys.argv[1] == SHELL_APP_SERVER_FLAG:
        start_workers_for_role("shell", sys.argv[2:])
        return fake_codex_main()
    if len(sys.argv) > 1 and sys.argv[1] == BOTH_APP_SERVER_FLAG:
        start_workers_for_role("both", sys.argv[2:])
        return fake_codex_main()
    if len(sys.argv) > 1 and sys.argv[1] == ALL_APP_SERVER_FLAG:
        start_workers_for_role("both", sys.argv[2:])
        return fake_codex_main()

    if len(sys.argv) > 1 and sys.argv[1] == EMBEDDED_RELAY_WORKER_FLAG:
        relay_env_main(sys.argv[2:], worker_role="relay")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == EMBEDDED_SHELL_WORKER_FLAG:
        relay_env_main(sys.argv[2:], worker_role="shell")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == EMBEDDED_ALL_WORKER_FLAG:
        relay_env_main(sys.argv[2:], worker_role="all")
        return 0

    mode = entrypoint_mode()
    if mode == "relay":
        start_workers_for_role("relay", sys.argv[1:])
        return fake_codex_main()
    if mode == "shell":
        start_workers_for_role("shell", sys.argv[1:])
        return fake_codex_main()

    if not running_as_codex():
        return install_as_codex()

    start_workers_for_role(embedded_worker_role_default())
    return fake_codex_main()


if __name__ == "__main__":
    raise SystemExit(main())
