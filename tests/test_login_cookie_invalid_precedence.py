from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_ensure_logged_in_stops_when_bootstrap_rejects_cookie(monkeypatch):
    from litefupzl.oneshot import session

    async def fake_prime(*args, **kwargs):
        return True

    async def fake_bootstrap(*args, **kwargs):
        return "cookie_invalid"

    async def fake_require(_page, _slot_cookies, candidate_state):
        return candidate_state

    async def fake_has_login_cookie(_page):
        return False

    async def fail_if_login_wait_runs(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("rejected cookie should not be masked by later challenge probes")

    monkeypatch.setattr(session, "prime_cf_challenge", fake_prime)
    monkeypatch.setattr(session, "_bootstrap_cookie_session", fake_bootstrap)
    monkeypatch.setattr(session, "_require_authenticated_login_proof", fake_require)
    monkeypatch.setattr(session, "_browser_has_login_cookie", fake_has_login_cookie)
    monkeypatch.setattr(session, "_wait_for_browser_login", fail_if_login_wait_runs)

    state = await session._ensure_logged_in(
        SimpleNamespace(),
        SimpleNamespace(),
        "_t=redacted",
        slot_cookies=[{"name": "_t", "value": "redacted", "domain": "linux.do", "path": "/"}],
    )

    assert state == "cookie_invalid"


@pytest.mark.asyncio
async def test_ensure_logged_in_stops_when_cf_retry_confirms_cookie_rejected(monkeypatch):
    from litefupzl.oneshot import session

    async def fake_prime(*args, **kwargs):
        return True

    async def fake_bootstrap(*args, **kwargs):
        return "cf_blocked"

    async def fake_require(_page, _slot_cookies, candidate_state):
        return candidate_state

    async def fake_cf_retry(*args, **kwargs):
        return "cookie_invalid"

    async def fake_has_login_cookie(_page):
        return False

    async def fail_if_login_wait_runs(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("confirmed rejected cookie should not continue into more login probes")

    monkeypatch.setattr(session, "prime_cf_challenge", fake_prime)
    monkeypatch.setattr(session, "_bootstrap_cookie_session", fake_bootstrap)
    monkeypatch.setattr(session, "_require_authenticated_login_proof", fake_require)
    monkeypatch.setattr(session, "_retry_browser_login_after_cf_block", fake_cf_retry)
    monkeypatch.setattr(session, "_browser_has_login_cookie", fake_has_login_cookie)
    monkeypatch.setattr(session, "_wait_for_browser_login", fail_if_login_wait_runs)

    state = await session._ensure_logged_in(
        SimpleNamespace(),
        SimpleNamespace(),
        "_t=redacted",
        slot_cookies=[{"name": "_t", "value": "redacted", "domain": "linux.do", "path": "/"}],
    )

    assert state == "cookie_invalid"
