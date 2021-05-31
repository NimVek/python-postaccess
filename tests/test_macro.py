"""Tests for `spf2acl` package."""
import pytest

from spf2acl import parser
from spf2acl.spf import Query


@pytest.mark.parametrize(
    ("macro", "expected"),
    [
        ("%{s}", "strong-bad@email.example.com"),
        ("%{o}", "email.example.com"),
        ("%{d}", "email.example.com"),
        ("%{d4}", "email.example.com"),
        ("%{d3}", "email.example.com"),
        ("%{d2}", "example.com"),
        ("%{d1}", "com"),
        ("%{dr}", "com.example.email"),
        ("%{d2r}", "example.email"),
        ("%{l}", "strong-bad"),
        ("%{l-}", "strong.bad"),
        ("%{lr}", "strong-bad"),
        ("%{lr-}", "bad.strong"),
        ("%{l1r-}", "strong"),
    ],
)
def test_macro(macro, expected):
    q = Query("strong-bad@email.example.com")
    m = parser.macro.parseString(macro, parseAll=True)[0]
    assert expected == m.expand(q)


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"),
        ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
        (
            "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
            "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
        ),
        (
            "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
            "3.2.0.192.in-addr.strong.lp._spf.example.com",
        ),
        (
            "%{d2}.trusted-domains.example.net",
            "example.com.trusted-domains.example.net",
        ),
        (
            "%{i}.%{l-.}.%{o}.%{d}.%{i}.%{v}.%{i}.very.long.example.net.%{d}",
            "192.0.2.3.strong.bad.email.example.com.email.example.com.192.0.2.3.in-addr.192.0.2.3.very.long.example.net.email.example.com",
        ),
    ],
)
def test_domain_ip4(domain, expected):
    q = Query("strong-bad@email.example.com", ip="192.0.2.3")
    d = parser.domain.parseString(domain, parseAll=True)[0]
    assert expected == d.expand(q)


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        (
            "%{ir}.%{v}._spf.%{d2}",
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com",
        ),
        ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
        (
            "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
            "bad.strong.lp.1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com",
        ),
        (
            "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.strong.lp._spf.example.com",
        ),
        (
            "%{d2}.trusted-domains.example.net",
            "example.com.trusted-domains.example.net",
        ),
        (
            "%{i}.%{l-.}.%{o}.%{d}.%{i}.%{v}.%{i}.very.long.example.net.%{d}",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1.strong.bad.email.example.com.email.example.com.2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1.ip6.2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1.very.long.example.net.email.example.com",
        ),
    ],
)
def test_domain_ip6(domain, expected):
    q = Query("strong-bad@email.example.com", ip="2001:db8::cb01")
    d = parser.domain.parseString(domain, parseAll=True)[0]
    assert expected == d.expand(q)
