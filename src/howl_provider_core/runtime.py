"""Restrictive policy, bounded transport and honest execution records."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import selectors
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ProviderError(ValueError):
    """Sanitized provider failure; never includes a server or subprocess body."""


class BudgetExceeded(ProviderError):
    """A call was blocked before dispatch."""


def _flag(name: str) -> bool:
    value = os.environ.get(name, "0").lower()
    if value not in {"0", "1", "false", "true", "no", "yes", ""}:
        raise ProviderError(f"invalid boolean policy variable: {name}")
    return value in {"1", "true", "yes"}


@dataclass(frozen=True)
class Policy:
    """A prohibition is monotonic; caller permission never overrides the environment."""

    allow_local: bool = False
    forbid_local: bool = False

    def __post_init__(self):
        if type(self.allow_local) is not bool or type(self.forbid_local) is not bool:
            raise ProviderError("local inference policy must use booleans")

    def local_allowed(self) -> bool:
        return (
            self.allow_local and not self.forbid_local and not _flag("HOWL_FORBID_LOCAL_INFERENCE")
        )

    def check_provider(self, provider: str) -> None:
        if provider == "ollama" and not self.local_allowed():
            raise ProviderError("local inference forbidden; Ollama requires explicit local opt-in")

    def check_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ProviderError("provider URL must be an HTTP(S) origin without credentials")
        host = parsed.hostname.lower().rstrip(".")
        try:
            local = not ipaddress.ip_address(host).is_global
        except ValueError:
            local = host == "localhost" or host.endswith((".localhost", ".local"))
            try:
                local = local or not ipaddress.ip_address(socket.inet_aton(host)).is_global
            except OSError:
                pass
        if local and not self.local_allowed():
            raise ProviderError("local or non-public inference endpoint forbidden")
        if parsed.scheme != "https" and not (local and self.local_allowed()):
            raise ProviderError("remote providers require HTTPS")

    def connect(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        """Resolve once, validate every destination, then connect to a literal IP.

        TLS still authenticates the original hostname. Rechecking at connection time
        also prevents a cached adapter from bypassing a newly imposed prohibition.
        """
        host, port = address
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not records:
            raise ProviderError("provider destination resolution failed")
        if not self.local_allowed() and any(
            not ipaddress.ip_address(record[4][0]).is_global for record in records
        ):
            raise ProviderError("resolved local or non-public inference endpoint forbidden")
        last_error = None
        for record in records:
            try:
                return socket.create_connection((record[4][0], port), timeout, source_address)
            except OSError as error:
                last_error = error
        raise ProviderError("provider connection failed") from last_error


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ProviderError("provider redirects are disabled")


def guarded_opener(policy: Policy):
    """No ambient proxies, redirects, or unvalidated socket destinations."""

    def connection_factory(cls):
        def create(host, **kwargs):
            connection = cls(host, **kwargs)
            connection._create_connection = policy.connect
            return connection

        return create

    class HTTP(urllib.request.HTTPHandler):
        def http_open(self, request):
            policy.check_url(request.full_url)
            return self.do_open(connection_factory(http.client.HTTPConnection), request)

    class HTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request):
            policy.check_url(request.full_url)
            return self.do_open(connection_factory(http.client.HTTPSConnection), request)

    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), HTTP(), HTTPS()
    )


@dataclass
class Execution:
    requested_provider: str
    selected_provider: str
    actual_provider: str
    adapter: str
    model: str | None = None
    requested_model: str | None = None
    deterministic: bool = False
    mocked: bool = False
    inference_occurred: bool | None = None
    remote: bool | None = None
    remote_observation: str | None = None
    fallback_reason: str | None = None
    elapsed_seconds: float = 0.0
    usage: dict | None = None
    cost: float | None = None

    def __post_init__(self):
        for value in (self.inference_occurred, self.remote):
            if value is not None and type(value) is not bool:
                raise ProviderError("invalid execution boolean metadata")
        if type(self.deterministic) is not bool or type(self.mocked) is not bool:
            raise ProviderError("invalid deterministic/mock metadata")
        if self.model is not None and not isinstance(self.model, str):
            raise ProviderError("invalid model metadata")

    def to_dict(self):
        return asdict(self)


@dataclass
class CallBudget:
    max_calls: int = 32
    calls: int = 0
    events: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if type(self.max_calls) is not int or self.max_calls < 0:
            raise ProviderError("max_calls must be a nonnegative integer")

    def consume(self, provider: str):
        with self._lock:
            if self.calls >= self.max_calls:
                raise BudgetExceeded("BUDGET_EXHAUSTED")
            self.calls += 1
            self.events.append({"call": self.calls, "provider": provider, "status": "STARTED"})


@dataclass(frozen=True)
class CommandConfig:
    argv: tuple[str, ...]
    remote: bool
    env_allowlist: tuple[str, ...] = ()
    timeout_seconds: float = 120
    max_output_bytes: int = 2 * 1024 * 1024
    model: str | None = None
    output_format: str = "text"

    def __post_init__(self):
        if not self.argv or any(not isinstance(arg, str) or "\0" in arg for arg in self.argv):
            raise ProviderError("command requires an explicit argv list")
        if self.remote is not True:
            raise ProviderError("command requires operator-declared remote execution")
        if not 0 < self.timeout_seconds <= 600 or not 0 < self.max_output_bytes <= 2 * 1024 * 1024:
            raise ProviderError("command timeout/output limit out of range")
        if self.output_format not in {"text", "json"}:
            raise ProviderError("command output_format must be text or json")
        name = Path(self.argv[0]).name.lower()
        if name in {
            "sh",
            "bash",
            "dash",
            "zsh",
            "fish",
            "cmd",
            "cmd.exe",
            "powershell",
            "pwsh",
            "ollama",
            "llama-cli",
            "llama-server",
            "vllm",
            "local-ai",
            "lms",
            "env",
        }:
            raise ProviderError("shell or local inference launcher forbidden")
        if any(arg in {"--oss", "--local", "--offline"} for arg in self.argv[1:]):
            raise ProviderError("local inference command option forbidden")

    @classmethod
    def read(cls, path: Path):
        """Only call for an explicitly supplied operator file, never artifact discovery."""
        if path.stat().st_size > 65536:
            raise ProviderError("command configuration exceeds 64 KiB")
        try:
            value = json.loads(path.read_text())
            if not isinstance(value, dict) or not isinstance(value.get("argv"), list):
                raise ProviderError("command configuration requires argv array")
            if not isinstance(value.get("env_allowlist", []), list):
                raise ProviderError("env_allowlist must be an array of variable names")
            value["argv"] = tuple(value["argv"])
            value["env_allowlist"] = tuple(value.get("env_allowlist", []))
            if any(
                not isinstance(name, str) or not name.isidentifier()
                for name in value["env_allowlist"]
            ):
                raise ProviderError("env_allowlist requires variable names")
            return cls(**value)
        except (TypeError, json.JSONDecodeError):
            raise ProviderError("invalid command configuration") from None


class CommandProvider:
    """Trusted operator commands, bounded data-only I/O, no shell interpolation."""

    def __init__(self, config: CommandConfig, policy: Policy | None = None):
        self.config = config
        self.policy = policy or Policy()
        if os.name != "posix":
            raise ProviderError("command provider currently requires POSIX process groups")
        executable = shutil.which(config.argv[0])
        if executable is None:
            raise ProviderError("command executable unavailable")
        resolved = str(Path(executable).resolve())
        CommandConfig((resolved, *config.argv[1:]), True)
        self.argv = (resolved, *config.argv[1:])

    @staticmethod
    def _terminate(process):
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        # Descendants may outlive the leader; kill the entire group even when it exited.
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait()

    def generate(self, prompt: str, cancel: threading.Event | None = None):
        config = self.config
        if len(prompt.encode()) > 2 * 1024 * 1024:
            raise ProviderError("command prompt exceeds 2 MiB")
        self.policy.check_provider("command")
        allowed = {"PATH", "HOME", "LANG", "SSL_CERT_FILE", "SSL_CERT_DIR"}
        allowed.update(config.env_allowlist)
        environment = {key: value for key, value in os.environ.items() if key in allowed}
        # A child Howl component must inherit the restrictive policy too.
        environment["HOWL_FORBID_LOCAL_INFERENCE"] = "1"
        started = time.monotonic()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        with (
            tempfile.TemporaryDirectory(prefix="howl-provider-") as workdir,
            subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=workdir,
                shell=False,
                start_new_session=os.name == "posix",
            ) as process,
        ):
            try:
                with selectors.DefaultSelector() as selector:
                    for name in buffers:
                        stream = getattr(process, name)
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, name)
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                    pending = memoryview(prompt.encode())
                    while selector.get_map():
                        if cancel and cancel.is_set():
                            raise ProviderError("command cancelled")
                        if time.monotonic() - started >= config.timeout_seconds:
                            raise ProviderError("command timed out")
                        for key, _ in selector.select(timeout=0.05):
                            if key.data == "stdin":
                                try:
                                    count = os.write(key.fd, pending[:65536]) if pending else 0
                                    pending = pending[count:]
                                except BrokenPipeError:
                                    pending = memoryview(b"")
                                if not pending:
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                            else:
                                chunk = os.read(key.fd, 65536)
                                if not chunk:
                                    selector.unregister(key.fileobj)
                                    continue
                                buffers[key.data].extend(chunk)
                                if len(buffers[key.data]) > config.max_output_bytes:
                                    raise ProviderError("command output limit exceeded")
                    while process.poll() is None:
                        if cancel and cancel.is_set():
                            raise ProviderError("command cancelled")
                        remaining = config.timeout_seconds - (time.monotonic() - started)
                        if remaining <= 0:
                            raise ProviderError("command timed out")
                        try:
                            process.wait(timeout=min(0.05, remaining))
                        except subprocess.TimeoutExpired:
                            pass
                if process.returncode != 0:
                    raise ProviderError(f"command failed with exit code {process.returncode}")
                try:
                    output = buffers["stdout"].decode("utf-8")
                except UnicodeDecodeError:
                    raise ProviderError("command output is not UTF-8") from None
                if not output.strip():
                    raise ProviderError("command returned empty output")
            finally:
                self._terminate(process)
        # Never persist explicitly passed credentials echoed by a subprocess.
        for key, value in environment.items():
            if value and any(
                marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD")
            ):
                output = output.replace(value, "[REDACTED]")
        reported = {}
        if config.output_format == "json":
            try:
                reported = json.loads(output)
                if not isinstance(reported, dict) or not isinstance(reported.get("text"), str):
                    raise TypeError()
                output = reported["text"]
                if not output.strip():
                    raise ValueError()
                for key in ("model", "provider"):
                    if reported.get(key) is not None and not isinstance(reported[key], str):
                        raise ValueError()
                if reported.get("usage") is not None and not isinstance(reported["usage"], dict):
                    raise ValueError()
                for key in ("deterministic", "mocked", "inference_occurred"):
                    if reported.get(key) is not None and type(reported[key]) is not bool:
                        raise ValueError()
            except (ValueError, TypeError):
                raise ProviderError("malformed command JSON response") from None
        return output, Execution(
            "command",
            "command",
            reported.get("provider") or "command",
            "command",
            model=reported.get("model"),
            requested_model=config.model,
            remote=True,
            remote_observation="OPERATOR_DECLARED",
            deterministic=reported.get("deterministic", False),
            mocked=reported.get("mocked", False),
            inference_occurred=reported.get("inference_occurred"),
            usage=reported.get("usage"),
            elapsed_seconds=time.monotonic() - started,
        )
