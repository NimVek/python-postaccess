"""Module that contains the command line app.

Why does this file exist, and why not put this in __main__?

You might be tempted to import things from __main__ later, but that will cause
problems: the code will get executed twice:

  - When you run `python -m spf2acl` python will execute
    ``__main__.py`` as a script. That means there won't be any
    ``spf2acl.__main__`` in ``sys.modules``.
  - When you import __main__ it will get executed again (as a module) because
    there's no ``spf2acl.__main__`` in ``sys.modules``.

Also see (1) from http://click.pocoo.org/5/setuptools/#setuptools-integration
"""
import argparse

from typing import List, Optional

import spf2acl


def main(args: Optional[List[str]] = None) -> int:
    """Console script for spf2acl.

    Args:
        args: Commandline arguments to parse

    Returns:
        exit code
    """
    parser = argparse.ArgumentParser(description=spf2acl.__summary__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"{ spf2acl.__name__ } { spf2acl.__version__ }",
    )
    parser.add_argument("_", nargs="*")

    parsed = parser.parse_args(args=args)

    print(f"Arguments: {parsed._}")
    print(f"Replace this message by putting your code into {__name__}.main")

    return 0
