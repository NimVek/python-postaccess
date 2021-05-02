"""Tests for `postaccess` package."""
import pytest

from postaccess import parser


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1", "v=spf1"),
        ("v=spf1 ip4:1.2.3.4", "v=spf1 ip4:1.2.3.4"),
    ],
)
def test_parser(record, expected):
    result = parser.record.parseString(record, parseAll=True)
    assert expected == str(result[0])
