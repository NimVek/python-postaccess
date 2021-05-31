import pytest

import spf2acl


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("title", "spf2acl"),
        (
            "summary",
            "Generator for Postscreen accesslist based on senders' SPF records.",
        ),
        ("uri", "https://github.com/NimVek/python-spf2acl/"),
        ("author", "NimVek"),
        ("email", "NimVek@users.noreply.github.com"),
        ("license", "GPL-3.0-or-later"),
    ],
)
def test_about(key, value):
    assert getattr(spf2acl, f"__{key}__") == value
