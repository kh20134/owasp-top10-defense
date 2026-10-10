REQUIRED = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy",
)


def test_vulnerable_profile_omits_headers_and_cookie_flags(client):
    response = client.get("/lab/a05/vuln/profile")
    assert response.status_code == 200
    for header in REQUIRED:
        assert header not in response.headers
    cookie = response.headers["Set-Cookie"]
    assert "prefs=open" in cookie
    lowered = cookie.lower()
    assert "httponly" not in lowered
    assert "secure" not in lowered
    assert "samesite" not in lowered

    debug = client.get("/lab/a05/vuln/debug")
    assert debug.status_code == 500
    assert "ZeroDivisionError" in debug.get_data(as_text=True)


def test_fixed_profile_sets_headers_and_cookie_flags(client):
    response = client.get("/lab/a05/fixed/profile")
    assert response.status_code == 200
    for header in REQUIRED:
        assert response.headers[header]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    cookie = response.headers["Set-Cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie

    debug = client.get("/lab/a05/fixed/debug")
    assert debug.status_code == 500
    text = debug.get_data(as_text=True)
    assert "ZeroDivisionError" not in text
    assert "요청을 처리할 수 없습니다." in text
