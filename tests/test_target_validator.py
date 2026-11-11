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
def test_mixed_dns_answers_are_rejected_for_allowlisted_hosts(monkeypatch):
    import ipaddress
    monkeypatch.setattr("scanner.target_validator.resolve_ips",lambda host:{ipaddress.ip_address('10.0.0.8'),ipaddress.ip_address('8.8.8.8')})
    with pytest.raises(TargetError):validate_target('https://mixed.example',['mixed.example'],True)
def test_link_local_metadata_and_unlisted_private_hostname_are_blocked(monkeypatch):
    import ipaddress
    monkeypatch.setattr("scanner.target_validator.resolve_ips",lambda host:{ipaddress.ip_address('169.254.169.254')})
    with pytest.raises(TargetError):validate_target('http://169.254.169.254/latest/meta-data',confirm=True)
    monkeypatch.setattr("scanner.target_validator.resolve_ips",lambda host:{ipaddress.ip_address('10.0.0.8')})
    with pytest.raises(TargetError):validate_target('http://unlisted.lab',confirm=True)
def test_public_ip_literal_needs_allowlist():
    with pytest.raises(TargetError):validate_target('https://8.8.8.8',confirm=True)
    assert validate_target('https://8.8.8.8',['8.8.8.8'],True)
def test_normalize():assert normalize_url("HTTP://LOCALHOST") == "http://localhost/"
