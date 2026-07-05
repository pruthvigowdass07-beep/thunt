from thunt.indicators import detect, host_of
from thunt.models import IndicatorType


def test_ipv4():
    assert detect("8.8.8.8") == (IndicatorType.IPV4, "8.8.8.8")


def test_ipv6():
    t, v = detect("2606:4700:4700::1111")
    assert t == IndicatorType.IPV6


def test_domain_lowercased():
    assert detect("GitHub.com") == (IndicatorType.DOMAIN, "github.com")


def test_url():
    assert detect("https://example.com/path?q=1") == (
        IndicatorType.URL, "https://example.com/path?q=1")


def test_md5_sha1_sha256():
    assert detect("44d88612fea8a8f36de82e1278abb02f")[0] == IndicatorType.MD5
    assert detect("da39a3ee5e6b4b0d3255bfef95601890afd80709")[0] == IndicatorType.SHA1
    assert detect(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )[0] == IndicatorType.SHA256


def test_defang_domain():
    assert detect("evil[.]com") == (IndicatorType.DOMAIN, "evil.com")


def test_defang_url_scheme():
    t, v = detect("hxxps://bad[.]tld/a")
    assert t == IndicatorType.URL
    assert v == "https://bad.tld/a"


def test_unknown():
    assert detect("just a sentence")[0] == IndicatorType.UNKNOWN


def test_host_of_url():
    assert host_of(IndicatorType.URL, "https://evil.com/x") == "evil.com"
    assert host_of(IndicatorType.DOMAIN, "evil.com") == "evil.com"
