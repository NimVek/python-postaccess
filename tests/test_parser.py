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
