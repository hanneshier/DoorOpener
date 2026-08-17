def make_client():
    from app import app as flask_app

    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def test_auth_status_defaults(client=None):
    client = client or make_client()
    resp = client.get("/auth/status")
    assert resp.status_code == 200
    data = resp.get_json()
    # OIDC disabled by default in example tests
    assert "oidc_enabled" in data
    assert data["oidc_authenticated"] in (False, True)


def test_auth_status_with_session():
    # Simulate OIDC being enabled by providing a truthy oauth object
    import app as app_module

    app_module.oauth = object()
    client = make_client()
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["oidc_user"] = "alice@example.com"
        s["oidc_groups"] = ["dooropener-users"]
    resp = client.get("/auth/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["oidc_authenticated"] is True
    assert data["user"] == "alice@example.com"
    assert "dooropener-users" in data.get("groups", [])


def test_open_door_pinless_oidc_allowed(monkeypatch):
    import app as app_module

    # Ensure policy allows pinless open and test mode avoids HA calls
    app_module.oauth = object()
    app_module.require_pin_for_oidc = False
    app_module.oidc_user_group = "dooropener-users"
    app_module.test_mode = True

    client = make_client()
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["oidc_user"] = "alice"
        s["oidc_groups"] = ["dooropener-users"]
        # Provide a valid future expiration for the OIDC session
        import time as _time

        s["oidc_exp"] = int(_time.time()) + 3600

    resp = client.post("/open-door", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert "Welcome home" in data["message"]


def test_open_door_pinless_blocked_when_require_pin(monkeypatch):
    import app as app_module

    app_module.require_pin_for_oidc = True
    app_module.oidc_user_group = ""  # any user allowed, but PIN still required
    app_module.test_mode = True

    client = make_client()
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["oidc_user"] = "bob"
        s["oidc_groups"] = ["dooropener-users"]
        import time as _time

        s["oidc_exp"] = int(_time.time()) + 3600

    resp = client.post("/open-door", json={})
    # No PIN provided -> should be a 400 requiring PIN
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "error"
    assert "PIN" in data["message"]


def test_open_door_pinless_expired_oidc(monkeypatch):
    import app as app_module

    app_module.oauth = object()
    app_module.require_pin_for_oidc = False
    app_module.oidc_user_group = "dooropener-users"
    app_module.test_mode = True

    client = make_client()
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["oidc_user"] = "dana"
        s["oidc_groups"] = ["dooropener-users"]
        # Expired exp in the past
        s["oidc_exp"] = 1

    resp = client.post("/open-door", json={})
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["status"] == "error"
    assert "expired" in data["message"].lower()


def test_login_sets_state_and_nonce_and_calls_authorize_redirect(monkeypatch):
    import app as app_module

    # Dummy provider to intercept authorize_redirect
    class _DummyProvider:
        def authorize_redirect(self, redirect_uri=None, state=None, nonce=None):
            assert redirect_uri
            assert state and nonce  # state/nonce must be provided
            from flask import redirect

            return redirect("/_dummy_redirect")

    class _DummyOAuth:
        def __init__(self):
            self.authentik = _DummyProvider()

    app_module.oauth = _DummyOAuth()

    client = make_client()
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert "/_dummy_redirect" in resp.headers.get("Location", "")


def test_oidc_callback_invalid_state(monkeypatch):
    import app as app_module

    # Ensure oauth object exists so callback doesn't short-circuit
    class _DummyOAuth:
        pass

    app_module.oauth = _DummyOAuth()

    client = make_client()
    # Seed expected state in session
    with client.session_transaction() as s:
        s["oidc_state"] = "expected"
        s["oidc_nonce"] = "nonce"
    # Provide wrong state so we fail before token exchange
    resp = client.get("/oidc/callback?state=wrong", follow_redirects=False)
    assert resp.status_code == 401


def test_open_door_pinless_blocked_when_group_not_allowed(monkeypatch):
    import app as app_module

    app_module.require_pin_for_oidc = False
    app_module.oidc_user_group = "dooropener-users"  # require specific group
    app_module.test_mode = True

    client = make_client()
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["oidc_user"] = "charlie"
        s["oidc_groups"] = ["some-other-group"]
        import time as _time

        s["oidc_exp"] = int(_time.time()) + 3600

    resp = client.post("/open-door", json={})
    # Not in allowed group -> PIN required path triggers 400 when missing
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "error"
    assert "PIN" in data["message"]


class _UserInfoResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _UserInfoProvider:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def load_server_metadata(self):
        return {"userinfo_endpoint": "https://auth.example.com/application/o/userinfo/"}

    def get(self, endpoint, token=None, timeout=None):
        self.calls.append({"endpoint": endpoint, "token": token, "timeout": timeout})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _configure_live_oidc_session(
    client,
    app_module,
    *,
    subject="11111111-1111-1111-1111-111111111111",
    userinfo_response=None,
):
    import time

    if userinfo_response is None:
        userinfo_response = _UserInfoResponse(200, {"sub": subject, "groups": ["dooropener-users"]})
    provider = _UserInfoProvider(userinfo_response)

    class _OAuth:
        authentik = provider

    app_module.oauth = _OAuth()
    app_module.require_pin_for_oidc = False
    app_module.oidc_user_group = "dooropener-users"
    app_module.live_permission_check = True
    app_module.live_permission_timeout_seconds = 5.0
    app_module.test_mode = True
    token_ref = app_module._store_oidc_access_token("user-access-token", subject, int(time.time()) + 3600)
    with client.session_transaction() as session_data:
        session_data["oidc_authenticated"] = True
        session_data["oidc_user"] = "alice"
        session_data["oidc_groups"] = ["dooropener-users"]
        session_data["oidc_exp"] = int(time.time()) + 3600
        session_data["oidc_sub"] = subject
        session_data["oidc_access_token_ref"] = token_ref
    return subject, provider


def test_live_permission_check_allows_current_member(client, monkeypatch):
    import app as app_module

    subject, provider = _configure_live_oidc_session(client, app_module)

    response = client.post("/open-door", json={})

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"
    assert provider.calls == [
        {
            "endpoint": "https://auth.example.com/application/o/userinfo/",
            "token": {"access_token": "user-access-token", "token_type": "Bearer"},
            "timeout": 5.0,
        }
    ]


def test_live_permission_check_rejects_revoked_token(client, monkeypatch):
    import app as app_module

    _configure_live_oidc_session(client, app_module, userinfo_response=_UserInfoResponse(401, {}))

    response = client.post("/open-door", json={})

    assert response.status_code == 401
    with client.session_transaction() as session_data:
        assert "oidc_authenticated" not in session_data
        assert "oidc_access_token_ref" not in session_data


def test_live_permission_check_rejects_removed_group(client, monkeypatch):
    import app as app_module

    subject = "11111111-1111-1111-1111-111111111111"
    _configure_live_oidc_session(
        client,
        app_module,
        subject=subject,
        userinfo_response=_UserInfoResponse(200, {"sub": subject, "groups": []}),
    )

    response = client.post("/open-door", json={})

    assert response.status_code == 403
    with client.session_transaction() as session_data:
        assert "oidc_authenticated" not in session_data


def test_live_permission_check_offers_pin_fallback_on_technical_failure(client, monkeypatch):
    import requests
    import app as app_module

    _configure_live_oidc_session(client, app_module, userinfo_response=requests.Timeout())

    response = client.post("/open-door", json={})

    assert response.status_code == 503
    assert response.get_json()["pin_fallback_available"] is True


def test_live_permission_check_offers_pin_fallback_on_userinfo_5xx(client):
    import app as app_module

    _configure_live_oidc_session(client, app_module, userinfo_response=_UserInfoResponse(503, {}))

    response = client.post("/open-door", json={})

    assert response.status_code == 503
    assert response.get_json()["pin_fallback_available"] is True


def test_live_permission_check_rejects_subject_mismatch(client):
    import app as app_module

    _configure_live_oidc_session(
        client,
        app_module,
        userinfo_response=_UserInfoResponse(
            200,
            {"sub": "22222222-2222-2222-2222-222222222222", "groups": ["dooropener-users"]},
        ),
    )

    response = client.post("/open-door", json={})

    assert response.status_code == 401
    with client.session_transaction() as session_data:
        assert "oidc_authenticated" not in session_data


def test_live_permission_check_allows_any_user_when_no_group_is_configured(client):
    import app as app_module

    subject = "11111111-1111-1111-1111-111111111111"
    _configure_live_oidc_session(
        client,
        app_module,
        subject=subject,
        userinfo_response=_UserInfoResponse(200, {"sub": subject}),
    )
    app_module.oidc_user_group = ""

    response = client.post("/open-door", json={})

    assert response.status_code == 200


def test_local_pin_remains_independent_of_live_oidc_check(client, monkeypatch):
    import app as app_module

    _configure_live_oidc_session(client, app_module)
    app_module.user_pins["pin-user"] = "1234"
    app_module.oauth.authentik.get = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("PIN access must not call OIDC UserInfo")
    )

    response = client.post("/open-door", json={"pin": "1234"})

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"


def test_live_oidc_callback_keeps_access_token_out_of_cookie_session(client):
    import time
    import app as app_module

    subject = "11111111-1111-1111-1111-111111111111"

    class _Provider:
        def authorize_access_token(self):
            return {
                "id_token": "dummy",
                "access_token": "secret-user-access-token",
                "userinfo": {
                    "aud": "dooropener-client",
                    "iss": "https://auth.example.com/application/o/dooropener",
                    "exp": int(time.time()) + 3600,
                    "nonce": "nonce",
                    "sub": subject,
                    "email": "alice@example.com",
                    "groups": ["dooropener-users"],
                },
            }

    class _OAuth:
        authentik = _Provider()

    app_module.oauth = _OAuth()
    app_module.live_permission_check = True
    app_module.oidc_client_id = "dooropener-client"
    app_module.oidc_issuer = "https://auth.example.com/application/o/dooropener"
    app_module.oidc_user_group = "dooropener-users"

    with client.session_transaction() as session_data:
        session_data["oidc_state"] = "state"
        session_data["oidc_nonce"] = "nonce"

    response = client.get("/oidc/callback?state=state", follow_redirects=False)

    assert response.status_code in (302, 303)
    with client.session_transaction() as session_data:
        assert session_data["oidc_sub"] == subject
        assert "access_token" not in session_data
        assert "secret-user-access-token" not in repr(dict(session_data))
        token_ref = session_data["oidc_access_token_ref"]
    assert app_module._get_oidc_access_token(token_ref)["access_token"] == "secret-user-access-token"


def test_live_permission_check_requires_login_after_token_store_is_cleared(client):
    import app as app_module

    _configure_live_oidc_session(client, app_module)
    with app_module._oidc_access_tokens_lock:
        app_module._oidc_access_tokens.clear()

    response = client.post("/open-door", json={})

    assert response.status_code == 401
