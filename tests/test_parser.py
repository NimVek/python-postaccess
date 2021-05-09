"""Tests for `postaccess` package."""
import pytest

from postaccess import parser


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1", "v=spf1"),
        ("v=spf1 ip4:1.2.3.4", "v=spf1 ip4:1.2.3.4"),
        ("v=spf1 ip6:::/64", "v=spf1 ip6:::/64"),
        ("v=spf1 a//64", "v=spf1 a//64"),
        ("v=spf1 mx:google.de/20", "v=spf1 mx:google.de/20"),
        ("v=spf1 include:google.de", "v=spf1 include:google.de"),
    ],
)
def test_parser(record, expected):
    result = parser.record.parseString(record, parseAll=True)
    assert expected == str(result[0])


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (
            "v=spf1 +mx a:colo.example.com/28 -all",
            "v=spf1 mx a:colo.example.com/28 -all",
        ),
        ("v=spf1 +mx -all", "v=spf1 mx -all"),
        (
            "v=spf1 +mx redirect=_spf.example.com",
            "v=spf1 mx redirect=_spf.example.com",
        ),
        ("v=spf1 a mx -all", "v=spf1 a mx -all"),
        (
            "v=spf1 include:example.com include:example.org -all",
            "v=spf1 include:example.com include:example.org -all",
        ),
        (
            "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all",
            "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all",
        ),
        (
            "v=spf1 mx -all exp=explain._spf.%{d}",
            "v=spf1 mx -all exp=explain._spf.%{d}",
        ),
    ],
)
def test_parser_rfc(record, expected):
    result = parser.record.parseString(record, parseAll=True)
    assert expected == str(result[0])


@pytest.mark.parametrize(
    ("record"),
    [
        ("v=spf1 ip4:192.0.2.1 ip4:192.0.2.129 -all"),
        ("v=spf1 mx:example.com -all"),
        ("v=spf1 ip4:192.0.2.0/24 mx -all"),
        ("v=spf1 a:authorized-spf.example.com -all"),
    ],
)
def test_parser_equal(record):
    result = parser.record.parseString(record, parseAll=True)
    assert record == str(result[0])
