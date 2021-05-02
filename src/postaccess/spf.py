import abc
import collections.abc
import enum
import re

import netaddr


class __Sequence(collections.abc.Sequence):
    def __init__(self, data):
        self.__data = data

    @property
    def data(self):
        return self.__data

    def __len__(self):
        return len(self.data)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return self.__class__(self.data[i])
        else:
            return self.data[i]


class SPF(__Sequence):
    @property
    def terms(self):
        return self.data

    @property
    def version(self):
        return "spf1"

    def __str__(self):
        result = "v=%s" % self.version
        if self.terms:
            result += " " + " ".join([str(x) for x in self.terms])
        return result


class Qualifier(str, enum.Enum):
    PASS = "+"
    FAIL = "-"
    NEUTRAL = "?"
    SOFT_FAIL = "~"


class Directive:
    def __init__(self, mechanism, qualifier=Qualifier.PASS):
        self.__mechanism = mechanism
        self.__qualifier = Qualifier(qualifier)

    @property
    def mechanism(self):
        return self.__mechanism

    @property
    def qualifier(self):
        return self.__qualifier

    def __str__(self):
        result = self.qualifier if self.qualifier != Qualifier.PASS else ""
        return result + str(self.mechanism)

    def __repr__(self):
        kwargs = ""
        if self.qualifier != Qualifier.PASS:
            kwargs += ", qualifier = %s" % self.qualifier
        return "%s(%r%s)" % (self.__class__.__name__, self.mechanism, kwargs)


class Mechanism(abc.ABC):
    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def __repr__(self):
        pass


class All(Mechanism):
    def __str__(self):
        return "all"

    def __repr__(self):
        return "%s()" % (self.__class__.__name__)


class IPNetwork(Mechanism):
    def __init__(self, network):
        self.__network = netaddr.IPNetwork(network)

    @property
    def network(self):
        return self.__network.cidr

    @property
    def version(self):
        return self.network.version

    @property
    def address(self):
        return self.network.ip

    @property
    def prefix_length(self):
        return self.network.prefixlen

    def __str__(self):
        suffix = (
            "/%d" % self.prefix_length
            if self.prefix_length != self.address.netmask_bits()
            else ""
        )
        return "ip%d:%s%s" % (self.version, self.address, suffix)

    def __repr__(self):
        return str(self)


class Macro:
    class Type(str, enum.Enum):
        SENDER = "s"
        SENDER_LOCAL = "l"
        SENDER_DOMAIN = "o"
        DOMAIN = "d"
        IP = "i"
        IP_DOMAIN = "p"
        IP_VERSION = "v"
        HELO = "h"

    def __init__(self, _type, length=None, reverse=False, delimiter="."):
        self.__type = Macro.Type(_type)
        self.__length = length
        self.__reverse = reverse
        self.__delimiter = "."

    @property
    def type(self):
        return self.__type

    @property
    def length(self):
        return self.__length

    @property
    def reverse(self):
        return self.__reverse

    @property
    def delimiter(self):
        return self.__delimiter

    def __str__(self):
        result = str(self.type)
        if self.length:
            result += "%d" % self.length
        if self.reverse:
            result += "r"
        if self.delimiter != ".":
            result += self.delimiter
        return result


class Domain(__Sequence):
    def __str__(self):
        result = ""
        for i in self.data:
            if isinstance(i, str):
                result += re.sub(r"[%_-]", r"%\g<0>", i)
            else:
                result += str(i)
        return result

    def __repr__(self):
        repr(self.data)
