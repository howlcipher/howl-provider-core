import socket
import sys
import threading
from unittest.mock import patch

import pytest

from howl_provider_core import (
    BudgetExceeded,
    CallBudget,
    CommandConfig,
    CommandProvider,
    Policy,
    ProviderError,
)


def test_prohibition_overrides_permission(monkeypatch):
    monkeypatch.setenv("HOWL_FORBID_LOCAL_INFERENCE", "1")
    policy = Policy(allow_local=True)
    with pytest.raises(ProviderError):
        policy.check_provider("ollama")
    for url in [
        "http://localhost:11434",
        "https://127.1",
        "https://[::1]",
        "https://127.0.0.2",
        "https://[::ffff:127.0.0.1]",
        "https://192.168.1.1",
    ]:
        with pytest.raises(ProviderError):
            policy.check_url(url)


def test_dns_blocked_before_connection():
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with (
        patch("socket.getaddrinfo", return_value=addresses),
        patch("socket.create_connection") as call,
    ):
        with pytest.raises(ProviderError):
            Policy().connect(("remote.example", 443))
        call.assert_not_called()


def test_dns_destination_pinned():
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    with (
        patch("socket.getaddrinfo", return_value=addresses),
        patch("socket.create_connection") as call,
    ):
        Policy().connect(("remote.example", 443))
        assert call.call_args.args[0] == ("8.8.8.8", 443)


def test_call_budget():
    budget = CallBudget(1)
    budget.consume("fake")
    with pytest.raises(BudgetExceeded):
        budget.consume("fake")
    assert budget.calls == 1


def command(code, **kwargs):
    return CommandProvider(CommandConfig((sys.executable, "-c", code), True, **kwargs))


def test_literal_stdin_and_environment(monkeypatch):
    monkeypatch.setenv("SECRET_UNRELATED", "secret-value")
    provider = command(
        'import sys,os; print(sys.stdin.read()); print(os.getenv("SECRET_UNRELATED"))'
    )
    text, metadata = provider.generate("$(touch malicious); `uname`")
    assert "$(touch malicious)" in text and "None" in text
    assert metadata.remote_observation == "OPERATOR_DECLARED"
    assert metadata.inference_occurred is None


@pytest.mark.parametrize(
    "code,message",
    [
        ('import sys; print("secret",file=sys.stderr); sys.exit(4)', "exit code 4"),
        ("import time; time.sleep(2)", "timed out"),
        ('print("x"*1000)', "output limit"),
        ("pass", "empty output"),
    ],
)
def test_failures_sanitized(code, message):
    provider = command(code, timeout_seconds=0.2, max_output_bytes=100)
    with pytest.raises(ProviderError, match=message) as error:
        provider.generate("test")
    assert "secret" not in str(error.value)


def test_cancellation():
    cancellation = threading.Event()
    cancellation.set()
    with pytest.raises(ProviderError, match="cancelled"):
        command("import time; time.sleep(2)").generate("test", cancellation)


@pytest.mark.parametrize(
    "argv", [("bash", "-c", "anything"), ("ollama", "run", "x"), ("codex", "--oss")]
)
def test_launchers_rejected(argv):
    with pytest.raises(ProviderError):
        CommandConfig(argv, True)


def test_secret_echo_redacted(monkeypatch):
    monkeypatch.setenv("EXPLICIT_API_KEY", "super-sensitive-key")
    output, _ = command(
        'import os; print(os.getenv("EXPLICIT_API_KEY"))', env_allowlist=("EXPLICIT_API_KEY",)
    ).generate("test")
    assert "super-sensitive-key" not in output
    assert "[REDACTED]" in output


def test_reported_model_distinct_from_requested():
    import json

    payload = json.dumps(
        {
            "text": "answer",
            "model": "actual-model",
            "provider": "fake-service",
            "inference_occurred": True,
            "usage": {"output_tokens": 2},
        }
    )
    output, metadata = command(
        "print(" + repr(payload) + ")", output_format="json", model="requested-model"
    ).generate("test")
    assert output == "answer"
    assert metadata.model == "actual-model"
    assert metadata.requested_model == "requested-model"
    assert metadata.actual_provider == "fake-service"
    _, text_metadata = command('print("answer")', model="requested").generate("test")
    assert text_metadata.model is None
    assert text_metadata.inference_occurred is None


def test_descendant_terminated(tmp_path):
    import os
    import pathlib
    import time

    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess,sys,time; "
        'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
        f'open({str(pid_file)!r},"w").write(str(child.pid)); time.sleep(30)'
    )
    with pytest.raises(ProviderError, match="timed out"):
        command(code, timeout_seconds=0.3).generate("test")
    pid = int(pid_file.read_text())
    for _ in range(20):
        status = pathlib.Path(f"/proc/{pid}/stat")
        if not status.exists() or status.read_text().split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        os.kill(pid, 9)
        pytest.fail("descendant was still running after timeout")


def test_cancellation_after_child_closes_pipes():
    cancellation = threading.Event()
    timer = threading.Timer(0.2, cancellation.set)
    timer.start()
    try:
        with pytest.raises(ProviderError, match="cancelled"):
            command(
                "import os,time; os.close(0); os.close(1); os.close(2); time.sleep(5)"
            ).generate("test", cancellation)
    finally:
        timer.cancel()
