import pytest

import postaccess


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("title", "Postaccess"),
        (
            "summary",
            "Generator for Postscreen accesslist based on senders' SPF records.",
        ),
        ("uri", "https://github.com/NimVek/python-postaccess/"),
        ("author", "NimVek"),
        ("email", "NimVek@users.noreply.github.com"),
        ("license", "GPL-3.0-or-later"),
    ],
)
def test_about(key, value):
    assert getattr(postaccess, f"__{key}__") == value
