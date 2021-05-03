import functools
import logging

import netaddr

from pyparsing import (
    CaselessLiteral,
    Char,
    Combine,
    Optional,
    ParseException,
    Word,
    nums,
)

from . import spf


__logger__ = logging.getLogger(__name__)

integer = Word(nums).setParseAction(lambda toks: int(toks[0]))


def __pa_network(s, loc, toks, version=4):
    try:
        return netaddr.IPAddress(toks[0], version=version)
    except netaddr.AddrFormatError as e:
        raise ParseException(s, loc, str(e))


def __pa_cidr_length(s, loc, toks, length=32):
    result = int(toks[0])
    if result > length:
        raise ParseException(s, loc, "prefix length must be between 0 and %d" % length)
    return result


ip4_network = Word(nums, nums + ".").setName("ip4-network").setParseAction(__pa_network)

ip4_cidr_length = (
    integer.copy().setName("ip4-cidr-length").setParseAction(__pa_cidr_length)
)

ip6_network = (
    Word(nums + ":.")
    .setName("ip6-network")
    .setParseAction(functools.partial(__pa_network, version=6))
)

ip6_cidr_length = (
    integer.copy()
    .setName("ip6-cidr-length")
    .setParseAction(functools.partial(__pa_cidr_length, length=128))
)


def __pa_ip(s, loc, toks):
    return spf.IPNetwork(toks[0]["network"])


ip4 = Combine(
    CaselessLiteral("ip4")
    + ":"
    + Combine(ip4_network + Optional("/" + ip4_cidr_length))("network")
).setParseAction(__pa_ip)

ip6 = Combine(
    CaselessLiteral("ip6")
    + ":"
    + Combine(ip6_network + Optional("/" + ip6_cidr_length))("network")
).setParseAction(__pa_ip)


def __pa_directive(s, loc, toks):
    return spf.Directive(toks["mechanism"], toks.get("qualifier", "+"))


directive = Combine(
    Optional(Char("+-?~")("qualifier")) + (ip4)("mechanism")
).setParseAction(__pa_directive)

term = directive

version = CaselessLiteral("v=spf1")


def __pa_record(s, loc, toks):
    return spf.SPF(toks.get("terms", []))


record = (version + term[...]("terms")).setParseAction(__pa_record)
