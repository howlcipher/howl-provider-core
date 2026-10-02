"""Restrictive policy, bounded transport and honest execution records."""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import re
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
    """Sanitized failure carrying an optional execution record and recovery policy."""

    def __init__(self, message, *, failure=None, execution=None):
        super().__init__(message)
        self.failure = failure or classify_failure(message)
        self.execution = execution


def classify_failure(text: str, *, exit_code=None) -> dict:
    """Classify bounded transient input, retaining only allowlisted static messages."""
    lower = text[:65536].lower()
    rules = (
        (
            "SESSION_LIMIT",
            ("session limit", "session quota"),
            "HUMAN_ACTION",
            "session limit reached",
        ),
        ("RATE_LIMIT", ("rate limit", "429"), "RETRYABLE", "rate limit reached"),
        (
            "AUTHENTICATION",
            ("api key", "unauthorized", "authentication", "401"),
            "NON_RETRYABLE",
            "authentication failed",
        ),
        (
            "CONTEXT_LIMIT",
            ("context limit", "context length", "token limit"),
            "NON_RETRYABLE",
            "context limit reached",
        ),
        ("TIMEOUT", ("timed out", "timeout"), "RETRYABLE", "command timed out"),
        ("CANCELLED", ("cancelled", "canceled"), "NON_RETRYABLE", "command cancelled"),
        (
            "PROVIDER_UNAVAILABLE",
            ("unavailable", "503", "overloaded"),
            "RETRYABLE",
            "provider unavailable",
        ),
        (
            "MALFORMED_RESPONSE",
            ("malformed", "empty output", "utf-8"),
            "REPAIRABLE",
            "malformed provider response",
        ),
        ("BUDGET_EXHAUSTED", ("budget_exhausted",), "NON_RETRYABLE", "BUDGET_EXHAUSTED"),
    )
    for category, markers, recovery, message in rules:
        if any(marker in lower for marker in markers):
            break
    else:
        category, recovery, message = "PROCESS_FAILURE", "NON_RETRYABLE", "provider process failed"
    return {
        "category": category,
        "recovery": recovery,
        "retryable": recovery == "RETRYABLE",
        "exit_code": exit_code,
        "sanitized_message": message,
    }


def reported_metadata(raw: str, adapter: str) -> dict:
    """Keep known metadata even when the completion field is invalid; no body retention."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    provider = {"claude-json": "claude", "openai-json": "openai", "gemini-json": "gemini"}.get(
        adapter
    ) or data.get("provider")
    model = data.get("model") or data.get("modelVersion")
    if adapter == "claude-json" and isinstance(data.get("modelUsage"), dict):
        model = next(iter(data["modelUsage"]), model)
    usage = data.get("usage") or data.get("usageMetadata")

    def numeric(value):
        if isinstance(value, dict):
            return {
                k: numeric(v)
                for k, v in value.items()
                if isinstance(k, str)
                and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}", k)
                and not any(
                    marker in k.lower()
                    for marker in ("secret", "password", "api_key", "authorization")
                )
                and (
                    isinstance(v, dict) or (type(v) in {int, float} and math.isfinite(v) and v >= 0)
                )
            }
        return value

    cost = data.get("total_cost_usd", data.get("cost"))
    request_id = data.get("session_id") or data.get("id") or data.get("request_id")
    inference = data.get("inference_occurred")
    if (
        inference is None
        and isinstance(usage, dict)
        and any(type(v) in {int, float} and v > 0 for v in numeric(usage).values())
    ):
        inference = True

    def identity(value):
        return (
            value
            if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_./:-]{1,200}", value)
            else None
        )

    return {
        "provider": identity(provider),
        "model": identity(model),
        "usage": numeric(usage) if isinstance(usage, dict) else None,
        "cost": cost if type(cost) in {int, float} and math.isfinite(cost) and cost >= 0 else None,
        "request_id": identity(request_id),
        "inference_occurred": inference if type(inference) is bool else None,
    }


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
    request_id: str | None = None
    raw_output_received: bool = False
    parse_status: str = "NOT_PARSED"
    repair_attempted: bool = False
    sampling: dict | None = None

    def __post_init__(self):
        for value in (self.inference_occurred, self.remote):
            if value is not None and type(value) is not bool:
                raise ProviderError("invalid execution boolean metadata")
        if type(self.deterministic) is not bool or type(self.mocked) is not bool:
            raise ProviderError("invalid deterministic/mock metadata")
        if self.model is not None and not isinstance(self.model, str):
            raise ProviderError("invalid model metadata")
        if self.cost is not None and not isinstance(self.cost, (int, float)):
            raise ProviderError("invalid cost metadata")

    def to_dict(self):
        return asdict(self)


class CLIResultAdapter:
    """Base class for decoding CLI subprocess output."""

    def decode(self, raw_output: str) -> tuple[str, dict]:
        raise NotImplementedError()


class RawTextAdapter(CLIResultAdapter):
    def decode(self, raw_output: str) -> tuple[str, dict]:
        if not raw_output.strip():
            raise ProviderError("command returned empty output")
        return raw_output, {}


class GenericJSONAdapter(CLIResultAdapter):
    def decode(self, raw_output: str) -> tuple[str, dict]:
        try:
            reported = json.loads(raw_output)
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
            return output, reported
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ProviderError("malformed command JSON response") from None


class ClaudeJSONAdapter(CLIResultAdapter):
    """Decodes Claude CLI JSON responses (--output-format json)."""

    def decode(self, raw_output: str) -> tuple[str, dict]:
        try:
            data = json.loads(raw_output)
            if not isinstance(data, dict):
                raise TypeError()
            if data.get("is_error") is True or data.get("subtype") == "error":
                failure = classify_failure(str(data.get("error") or data.get("result") or ""))
                raise ProviderError(
                    "Claude CLI error: " + failure["sanitized_message"], failure=failure
                )
            text = data.get("result")
            if text is None:
                text = data.get("text")
            if not isinstance(text, str) or not text.strip():
                raise ValueError()
            model = None
            if isinstance(data.get("modelUsage"), dict) and data["modelUsage"]:
                model = next(iter(data["modelUsage"].keys()))
            elif isinstance(data.get("model"), str):
                model = data["model"]
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
            cost = data.get("total_cost_usd")
            if cost is not None and not isinstance(cost, (int, float)):
                cost = None
            req_id = data.get("session_id") or data.get("uuid")
            return text, {
                "model": model,
                "provider": "claude",
                "usage": usage,
                "cost": float(cost) if cost is not None else None,
                "request_id": str(req_id) if req_id else None,
                "inference_occurred": True,
            }
        except ProviderError:
            raise
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ProviderError("malformed Claude JSON response") from None


class OpenAIJSONAdapter(CLIResultAdapter):
    """Decodes OpenAI / Codex CLI responses."""

    def decode(self, raw_output: str) -> tuple[str, dict]:
        try:
            data = json.loads(raw_output)
            if not isinstance(data, dict):
                raise TypeError()
            choices = data.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message", {})
                text = msg.get("content") or choices[0].get("text")
            else:
                text = data.get("text")
            if not isinstance(text, str) or not text.strip():
                raise ValueError()
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
            return text, {
                "model": data.get("model"),
                "provider": "openai",
                "usage": usage,
                "request_id": data.get("id"),
                "inference_occurred": True,
            }
        except ProviderError:
            raise
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ProviderError("malformed OpenAI/Codex JSON response") from None


class GeminiJSONAdapter(CLIResultAdapter):
    """Decodes Gemini CLI responses."""

    def decode(self, raw_output: str) -> tuple[str, dict]:
        try:
            data = json.loads(raw_output)
            if not isinstance(data, dict):
                raise TypeError()
            candidates = data.get("candidates")
            if isinstance(candidates, list) and candidates:
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            else:
                text = data.get("text")
            if not isinstance(text, str) or not text.strip():
                raise ValueError()
            raw_meta = data.get("usageMetadata")
            usage = raw_meta if isinstance(raw_meta, dict) else None
            return text, {
                "model": data.get("modelVersion") or data.get("model"),
                "provider": "gemini",
                "usage": usage,
                "inference_occurred": True,
            }
        except ProviderError:
            raise
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ProviderError("malformed Gemini JSON response") from None


ADAPTERS: dict[str, type[CLIResultAdapter]] = {
    "text": RawTextAdapter,
    "raw-text": RawTextAdapter,
    "json": GenericJSONAdapter,
    "generic-json": GenericJSONAdapter,
    "claude-json": ClaudeJSONAdapter,
    "openai-json": OpenAIJSONAdapter,
    "gemini-json": GeminiJSONAdapter,
}


@dataclass
class CallBudget:
    max_calls: int = 32
    calls: int = 0
    events: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if (
            type(self.max_calls) is not int
            or self.max_calls < 0
            or type(self.calls) is not int
            or not 0 <= self.calls <= self.max_calls
        ):
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
    adapter: str | None = None

    def __post_init__(self):
        if not self.argv or any(not isinstance(arg, str) or "\0" in arg for arg in self.argv):
            raise ProviderError("command requires an explicit argv list")
        if self.remote is not True:
            raise ProviderError("command requires operator-declared remote execution")
        if not 0 < self.timeout_seconds <= 600 or not 0 < self.max_output_bytes <= 2 * 1024 * 1024:
            raise ProviderError("command timeout/output limit out of range")
        fmt = self.adapter or self.output_format
        if fmt not in ADAPTERS:
            raise ProviderError("command output_format / adapter must be a supported format")
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
                    failure = classify_failure(
                        buffers["stdout"].decode("utf-8", errors="replace")
                        + buffers["stderr"].decode("utf-8", errors="replace"),
                        exit_code=process.returncode,
                    )
                    raise ProviderError(
                        f"command failed with exit code {process.returncode}: "
                        + failure["sanitized_message"],
                        failure=failure,
                    )
                try:
                    output = buffers["stdout"].decode("utf-8")
                except UnicodeDecodeError:
                    raise ProviderError("command output is not UTF-8") from None
                if not output.strip():
                    raise ProviderError("command returned empty output")
            except ProviderError as error:
                meta = reported_metadata(
                    buffers["stdout"].decode("utf-8", errors="replace"),
                    config.adapter or config.output_format,
                )
                error.execution = Execution(
                    "command",
                    "command",
                    meta.get("provider") or "command",
                    config.adapter or config.output_format,
                    model=meta.get("model"),
                    requested_model=config.model,
                    remote=True,
                    remote_observation="OPERATOR_DECLARED",
                    elapsed_seconds=time.monotonic() - started,
                    usage=meta.get("usage"),
                    cost=meta.get("cost"),
                    request_id=meta.get("request_id"),
                    inference_occurred=meta.get("inference_occurred"),
                    raw_output_received=bool(buffers["stdout"]),
                    parse_status="FAILED",
                ).to_dict()
                error.failure.update(
                    provider=error.execution["actual_provider"], model=error.execution["model"]
                )
                raise
            finally:
                self._terminate(process)
        # Never persist explicitly passed credentials echoed by a subprocess.
        for key, value in environment.items():
            if value and any(
                marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD")
            ):
                output = output.replace(value, "[REDACTED]")
        adapter_name = config.adapter or config.output_format
        adapter_cls = ADAPTERS[adapter_name]
        raw = output
        try:
            output, reported = adapter_cls().decode(raw)
        except ProviderError as error:
            meta = reported_metadata(raw, adapter_name)
            error.execution = Execution(
                "command",
                "command",
                meta.get("provider") or "command",
                adapter_name,
                model=meta.get("model"),
                requested_model=config.model,
                remote=True,
                remote_observation="OPERATOR_DECLARED",
                elapsed_seconds=time.monotonic() - started,
                usage=meta.get("usage"),
                cost=meta.get("cost"),
                request_id=meta.get("request_id"),
                inference_occurred=meta.get("inference_occurred"),
                raw_output_received=True,
                parse_status="FAILED",
            ).to_dict()
            error.failure.update(
                provider=error.execution["actual_provider"], model=meta.get("model")
            )
            raise
        safe_meta = reported_metadata(raw, adapter_name)
        for key in ("model", "usage", "cost", "request_id"):
            reported[key] = safe_meta.get(key)
        if safe_meta.get("provider"):
            reported["provider"] = safe_meta["provider"]
        return output, Execution(
            "command",
            "command",
            reported.get("provider") or "command",
            adapter_name,
            model=reported.get("model"),
            requested_model=config.model,
            remote=True,
            remote_observation="OPERATOR_DECLARED",
            deterministic=reported.get("deterministic", False),
            mocked=reported.get("mocked", False),
            inference_occurred=reported.get("inference_occurred"),
            usage=reported.get("usage"),
            cost=reported.get("cost"),
            request_id=reported.get("request_id"),
            elapsed_seconds=time.monotonic() - started,
            raw_output_received=True,
            parse_status="VALID",
        )
