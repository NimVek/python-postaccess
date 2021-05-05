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
    alphanums,
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
    __logger__.info(toks)
    return spf.IPNetwork(toks["network"])


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


def __pa_all(s, loc, toks):
    return spf.All()


all = CaselessLiteral("all").setParseAction(__pa_all)


def __pa_macro(s, loc, toks):
    return spf.Macro(
        toks.get("macro"),
        length=toks.get("length"),
        reverse=bool(toks.get("reverse")),
        delimiter=toks.get("delimiter", "."),
    )


macro = Combine(
    "%{"
    + Char("slodiphv")("macro")
    + Optional(integer)("length")
    + Optional("r")("reverse")
    + Optional(Word(".-+,/_="))("delimiter")
    + "}"
).setParseAction(__pa_macro)

macro_escape = Combine("%" + Char("%_-")).setParseAction(lambda toks: toks[0][1])

domain = (macro ^ macro_escape ^ Word(alphanums + "-."))[...].setParseAction(
    lambda toks: spf.Domain(toks)
)

include = Combine(CaselessLiteral("include") + ":" + domain("domain")).setParseAction(
    lambda toks: spf.Include(toks["domain"])
)


def __pa_a_mx(s, loc, toks, cls=spf.A):
    return cls(
        domain=toks.get("domain"),
        ipv4_prefix_length=toks.get("ip4", 32),
        ipv6_prefix_length=toks.get("ip6", 128),
    )


a = Combine(
    CaselessLiteral("a")
    + Optional(":" + domain("domain"))
    + Optional("/" + ip4_cidr_length("ip4"))
    + Optional("//" + ip6_cidr_length("ip6"))
).setParseAction(__pa_a_mx)

mx = Combine(
    CaselessLiteral("mx")
    + Optional(":" + domain("domain"))
    + Optional("/" + ip4_cidr_length("ip4"))
    + Optional("//" + ip6_cidr_length("ip6"))
).setParseAction(functools.partial(__pa_a_mx, cls=spf.MX))


def __pa_directive(s, loc, toks):
    return spf.Directive(toks["mechanism"], toks.get("qualifier", "+"))


directive = Combine(
    Optional(Char("+-?~")("qualifier"))
    + (all ^ include ^ a ^ mx ^ ip4 ^ ip6)("mechanism")
).setParseAction(__pa_directive)

term = directive

version = CaselessLiteral("v=spf1")


def __pa_record(s, loc, toks):
    return spf.SPF(toks.get("terms", []))


record = (version + term[...]("terms")).setParseAction(__pa_record)
