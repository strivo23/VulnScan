import pytest
from scanner.target_validator import validate_target,TargetError,normalize_url,validate_redirect

def test_local_target_requires_confirmation():
    with pytest.raises(TargetError):validate_target("http://127.0.0.1",confirm=False)
    assert validate_target("http://127.0.0.1:8081",confirm=True).endswith(":8081/")
def test_rejects_non_http_credentials_and_public(monkeypatch):
    for url in ("ftp://127.0.0.1","http://u:p@127.0.0.1"):
        with pytest.raises(TargetError):validate_target(url,confirm=True)
    monkeypatch.setattr("scanner.target_validator.resolve_ips",lambda host:{__import__('ipaddress').ip_address('8.8.8.8')})
    with pytest.raises(TargetError):validate_target("https://unlisted.example",confirm=True)
    assert validate_target("https://allowed.example",["allowed.example"],True)
def test_redirect_scope(monkeypatch):
    assert validate_redirect("http://127.0.0.1/","/next")
    with pytest.raises(TargetError):validate_redirect("https://public.example/","http://127.0.0.1/")
def test_normalize():assert normalize_url("HTTP://LOCALHOST") == "http://localhost/"
