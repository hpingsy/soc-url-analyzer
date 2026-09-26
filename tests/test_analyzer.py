import json
import socket

import pytest

from soc_url_analyzer import analyze_url


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Analysis must not access the network")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, fail)


@pytest.mark.parametrize(
    "url,scheme,host",
    [
        ("https://example.com/path?q=value#fragment", "https", "example.com"),
        ("HTTP://EXAMPLE.COM", "http", "example.com"),
        ("https://example.com.:443/", "https", "example.com"),
        ("https://localhost", "https", "localhost"),
        ("https://bücher.example", "https", "xn--bcher-kva.example"),
        ("https://[2001:db8::1]/", "https", "2001:db8::1"),
        ("http://192.0.2.1", "http", "192.0.2.1"),
    ],
)
def test_valid_urls(url, scheme, host):
    result = analyze_url(url)
    assert result["valid"]
    assert result["scheme"] == scheme
    assert result["hostname"] == host
    assert result["errors"] == []
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize(
    "url",
    [
        None,
        42,
        {},
        b"https://example.com",
        "",
        "example.com",
        "//example.com",
        "ftp://example.com",
        "javascript:alert(1)",
        "https:///path",
        "https://",
        "https://?q=a",
        "https://example.com:abc",
        "https://example.com:65536",
        "https://example.com:0",
        "https://example.com:",
        "https://example.com:-1",
        " https://example.com",
        "https://exam\nple.com",
        "https://example.com/\x00",
        "https://example.com/a b",
        "https://example.com\\@evil.example",
        "https://example.com/%GG",
        "https://example.com/%",
        "https://bad_host.example",
        "https://-bad.example",
        "https://bad-.example",
        "https://a..example",
        "https://" + "a" * 64 + ".example",
        "https://999.1.1.1",
        "https://127.1",
        "https://[::1",
        "https://[::1]junk",
        "https://[v1.foo]",
        "https://[fe80::1%25eth0]",
        "https://user@@example.com",
        "https://%65xample.com",
    ],
)
def test_invalid_urls(url):
    result = analyze_url(url)
    assert not result["valid"]
    assert result["errors"]
    assert result["scheme"] is None
    assert result["hostname"] is None
    assert result["findings"] == []
    assert not result["suspicious"]
    json.dumps(result)


@pytest.mark.parametrize(
    "url,code",
    [
        ("http://example.com", "unencrypted_http"),
        ("https://trusted.example@other.example", "embedded_credentials"),
        ("https://192.0.2.1", "ip_literal"),
        ("https://[::1]", "ip_literal"),
        ("https://xn--bcher-kva.example", "idn_hostname"),
        ("https://a.b.c.d.example", "many_labels"),
        ("https://example.com/" + "a" * 2048, "long_url"),
        ("https://example.com:8080", "unusual_port"),
        ("https://example.com/file.%65Xe?download=1", "executable_path"),
    ],
)
def test_findings(url, code):
    result = analyze_url(url)
    assert result["valid"]
    assert result["suspicious"]
    assert code in {finding["code"] for finding in result["findings"]}


def test_multiple_findings_and_actual_hostname():
    result = analyze_url("http://trusted.example@192.0.2.1:8080/file.exe")
    assert result["hostname"] == "192.0.2.1"
    assert {f["code"] for f in result["findings"]} == {
        "unencrypted_http",
        "embedded_credentials",
        "ip_literal",
        "unusual_port",
        "executable_path",
    }


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "https://example.com:443/path",
        "https://example.com/file.exe.txt",
        "https://example.com/?file=app.exe",
        "https://example.com/" + "a" * (2048 - len("https://example.com/")),
    ],
)
def test_no_findings(url):
    result = analyze_url(url)
    assert result["valid"]
    assert not result["suspicious"]
    assert result["findings"] == []


@pytest.mark.parametrize(
    "url,blocklist",
    [
        ("https://bad.example", {"bad.example"}),
        ("https://login.bad.example", {"bad.example"}),
        ("https://LOGIN.BAD.EXAMPLE.", {"Bad.Example."}),
        ("https://bücher.example", {"BÜCHER.EXAMPLE"}),
        ("https://192.0.2.1", {"192.0.2.1"}),
    ],
)
def test_blocked_domain(url, blocklist):
    result = analyze_url(url, domain_blocklist=blocklist)
    assert result["valid"]
    assert result["suspicious"]
    assert "blocked_domain" in {finding["code"] for finding in result["findings"]}


@pytest.mark.parametrize(
    "url,blocklist",
    [
        ("https://bad.example", ()),
        ("https://notbad.example", {"bad.example"}),
        ("https://bad.example.evil", {"bad.example"}),
        ("https://example", {"bad.example"}),
        ("https://192.0.2.2", {"192.0.2.1"}),
    ],
)
def test_domain_not_blocked(url, blocklist):
    result = analyze_url(url, domain_blocklist=blocklist)
    assert result["valid"]
    assert "blocked_domain" not in {finding["code"] for finding in result["findings"]}


def test_invalid_url_never_checks_blocklist():
    assert analyze_url("not a URL", domain_blocklist={"bad.example"})["findings"] == []
