"""Tests for `spf2acl` package."""
import pytest

from spf2acl import main


def test_command_line_interface(capsys):
    """Test the CLI."""
    main.main(args=[])
    captured = capsys.readouterr()
    assert "spf2acl.main.main" in captured.out


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        ("--help", "show this help message and exit"),
        ("-h", "show this help message and exit"),
        ("--version", "spf2acl "),
    ],
)
def test_standard_arguments(capsys, argument, expected):
    with pytest.raises(SystemExit):
        main.main(args=[argument])
    captured = capsys.readouterr()
    assert expected in captured.out
