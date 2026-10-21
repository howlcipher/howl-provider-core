from howl_provider_core import REDACTED, redact, scrub, secret_env_values


def test_known_token_shapes_and_assignments_are_redacted():
    text = (
        "key sk-abcdefghijklmnop gh token ghp_abcdefghijklmnopqrst pat github_pat_11AB "
        "aws AKIAABCDEFGHIJKLMNOP authorization: Bearer abc.def password=hunter2 api-key: x1 "
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
    )
    out = redact(text)
    for leaked in ("sk-abc", "ghp_", "github_pat_", "AKIA", "abc.def", "hunter2", "x1", "MIIE"):
        assert leaked not in out, leaked
    assert out.count(REDACTED) >= 8


def test_literal_secrets_are_redacted_even_without_a_known_shape():
    assert (
        redact("my secret is plainvalue42", secrets=["plainvalue42"]) == "my secret is [REDACTED]"
    )
    assert redact("nothing", secrets=["", None or ""]) == "nothing"


def test_scrub_walks_json_and_drops_secret_keys():
    value = {
        "Authorization": "x",
        "nested": [{"token": "t", "note": "sk-abcdefghijklmnop"}],
        "n": 1,
    }
    assert scrub(value) == {
        "Authorization": REDACTED,
        "nested": [{"token": REDACTED, "note": REDACTED}],
        "n": 1,
    }


def test_secret_env_values_picks_credential_like_names():
    env = {"OPENAI_API_KEY": "k1", "GH_TOKEN": "t1", "PATH": "/usr/bin", "EMPTY_SECRET": ""}
    assert sorted(secret_env_values(env)) == ["k1", "t1"]
