import itertools
import json
import sys
import warnings

warnings.filterwarnings("ignore")

import stem.exit_policy
import stem.util.connection
import stem.util.str_tools
import stem.util.tor_tools
import stem.version
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import stem.descriptor.hidden_service as hidden_service

IPV4 = [
    "0.0.0.0", "255.255.255.255", "127.0.0.1", "192.168.0.50", "256.0.0.0",
    "-1.0.0.0", "0.0.0", "0.0.0.", "0.0.0.a", "1.2.3.4.5", "01.02.03.04",
    "1.2.3.04", " 1.2.3.4", "1.2.3.4\n", "1.2.3.4 ", "", "1..2.3", "0x7f.0.0.1",
    "1.2.3.4/24", "１.２.３.４", "1.2.3.+4", "1.2.3.4\x00",
    "1.2.3", "1.2.3.256", "999.1.1.1", "1.1.1.1.", ".1.1.1.1",
]

IPV6 = [
    "::", "::1", "fe80::0202:b3ff:fe1e:8329", "[::1]", "[fe80::]", "fe80:::b3ff",
    "1::2::3", "12345::", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9",
    "[::1", "::1]", "fe80::1%eth0", "", "::g", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
    "[FE80::0202:b3ff:fe1e:8329]", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8::",
    " ::1", "::1 ", "::1\n", "0:0:0:0:0:0:0:0", "::1.2.3.4.5", "1::2:3.4.5.6",
]

PORTS = [
    "0", "1", "80", "65535", "65536", "a", "", "-1", "+80", "080", "8 0", " 80",
    "80 ", "80\n", "123456", "١٢", "0x50", "1e2", "00", "0080", "99999",
    "65535 ", "1_0",
]

PRIVATE = [
    "10.0.0.1", "172.16.0.1", "172.31.255.255", "172.32.0.1", "192.168.0.1",
    "127.0.0.1", "169.254.1.1", "8.8.8.8", "0.0.0.0", "100.64.0.1", "bad",
    "255.255.255.255", "192.169.0.1", "11.0.0.1", "",
]

EXPAND = ["::", "::1", "fe80::0202:b3ff:fe1e:8329", "1:2:3:4:5:6:7:8", "::ffff:1.2.3.4", "bad", "", "[::1]"]

MASKS = [
    "255.255.255.255", "255.255.255.0", "0.0.0.0", "255.0.255.0", "255.255.255.254",
    "1.2.3.4", "bad", "255.255.255.255.0", "255.255.0.0", "128.0.0.0", "", "0.0.0.255",
]

FINGERPRINTS = [
    "A" * 40, "a" * 40, "$" + "A" * 40, "A" * 39, "A" * 41, "G" * 40, "", "$",
    "$$" + "A" * 40, "A" * 40 + "\n", " " + "A" * 40, "0123456789ABCDEFabcdef0123456789ABCDEF01",
]

NICKNAMES = [
    "caerSidi", "a", "a" * 19, "a" * 20, "", "has space", "under_score", "dash-ed",
    "ümlaut", "123", "ab\n", "A1b2", "tor.", "nick\x00",
]

IDS = ["1", "a" * 16, "a" * 17, "", "ab_c", "ab-c", "12\n", "A1", "0"]

ONIONS = [
    "gfzprpioee3hoppz", "a" * 16, "A" * 16, "a" * 15, "a" * 17, "a" * 56, "a" * 55,
    "1" * 16, "z" * 16, "oekn5sqrvcu4wote", "2" * 56, "8" * 16, "",
]

SIZES = [0, 1, -1, 1023, 1024, 1536, 1048575, 1048576, 1073741824, 2 ** 40, 2 ** 50, 2 ** 52,
         3.5, 0.5, 0.125, 127, 128, 129, 1e15, 12345678, -2048, 100, 1000, 999999]

TIMES = [0, 1, 59, 60, 61, 90, 3599, 3600, 86399, 86400, 90061, 172800, -5, -3600, 0.5, 1.5, 59.99]

SHORT_LABELS = [
    "00:00", "01:30", "1:30", "01:01:01", "1-00:00:00", "2-03:04:05", "00:00:00:00", "",
    "a:b", "1:2:3:4", "01:30.5", "-1:00", "1-2", "1-", "-", "::", "99999999-00:00:00",
    "1:60", "00:60", "1 :30", "+1:30", "1_0:30", "1e1:30",
]

TIMESTAMPS = [
    "2012-03-01 17:15:27", "2012-3-1 17:15:27", "2012-03-01T17:15:27",
    "2012-03-01 17:15:27 extra", "2012-13-01 00:00:00", "2012-02-30 00:00:00",
    "0000-01-01 00:00:00", "", "2012-03-01 24:00:00", "2012-03-01 17:15:60",
    "2012-03-01 17:15:2", " 2012-03-01 17:15:27", "2012-03-01 17:15:27\n",
    "9999-12-31 23:59:59", "2012-02-29 12:00:00", "2013-02-29 12:00:00",
    "２０１２-03-01 17:15:27",
]

ISO_TIMESTAMPS = [
    "2012-03-01T17:15:27.123456", "2012-03-01T17:15:27", "2012-03-01 17:15:27.123456",
    "2012-03-01T17:15:27.12345", "2012-03-01T17:15:27.1234567", "2012-03-01T17:15:27.",
    "2012-03-01T17:15:27.12345a", "2012-03-01T17:15:27.000000", "", "garbage",
    "2012-03-01T17:15:27.123456.1",
]

CAMEL = [
    ("hello_world", "_", " "), ("HELLO_WORLD", "_", " "), ("a_b_c", "_", ""), ("", "_", " "),
    ("a__b", "_", " "), ("x", "_", " "), ("some-thing here", "-", "+"), ("_lead", "_", " "),
    ("trail_", "_", " "), ("ünï_cödé", "_", " "), ("mixedCase_wORD", "_", " "),
]

SPLITS = [("hello world", size) for size in (1, 2, 3, 5, 11, 12, 100)] + [("", 3), ("abc", 0), ("äöü", 2)]

CROP_MESSAGES = [
    "hello world",
    "this is a longer message with several words in it",
    "supercalifragilisticexpialidocious",
    "a, b. c, d.",
    "trailing space ",
    "ünïcödé wörds hëre ok",
    "word",
]

VERSIONS = [
    "0.2.2.23-alpha (git-b85eb949b528f4d7)", "0.2.1.30", "0.1.0.0", "1.2.3", "1.2.3.4-rc",
    "0.2.2.23-alpha-dev", "0.2.4.0-alpha-dev (git-xxx)", "0.2", "", "abc", "1.2.3.4.5",
    "0.2.2.23-alpha extra", "  0.2.2.1", "0.2.2.1 ", "0.2.2.1\n", "0.2.2.1-", "0.2.2.1-beta",
    "0.2.2.1-dev", "0.2.2.1 (git-abc)", "0.2.2.1-dev (git-abc)", "10.20.30.40", "0.2.4.5-alpha-dev",
    "1.2.3 (git-ef0bc7f8f26a917c)", "1.2.3-alpha", "1.2.3-alpha-dev (git-1)", "00.02.02.01",
    "0.2.2.1.", "-1.2.3", "1.-2.3", "0.2.2.1 (git-)", "0.2.2.1 (GIT-abc)", "0.2.2.23-alpha-dev-extra",
]

RULES = [
    "accept *:*", "reject *:*", "accept *:80", "accept *:80-443", "accept 127.0.0.1:80",
    "accept 87.0.0.1/24:80", "accept 156.5.38.3/255.255.0.255:80",
    "accept [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:80",
    "accept [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]/32:80", "accept 10.0.0.1/32:80",
    "accept 192.168.0.1/255.255.255.0:80", "accept [::]/32:*", "accept [::]/128:*",
    "accept6 *:*", "reject6 *:*", "accept6 [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:*",
    "accept *4:*", "accept *6:*", "accept6 *4:*", "accept6 *6:*", "reject *:80",
    "accept 192.168.0.1:*", "reject *4:*", "reject 127.0.0.1/0:*", "reject 127.0.0.1/0.0.0.0:*",
    "reject 127.0.0.1/16:*", "reject 127.0.0.1/32:*", "accept 192.168.0.1:0-65535",
    "accept 192.168.0.1:1-65535", "accept 192.168.0.1:2-65535", "accept 192.168.0.1:1-65534",
    "accept    *:80", "accept\t*:*", "accept\n*:*", "acceptt *:*", "blarg *:*", " *:*", "*:*", "",
    "accept", "reject", "reject */16:*", "reject 127.0.0.1/*:*", "reject *:0-*", "reject *:*-15",
    "accept 256.0.0.0:*", "accept -1.0.0.0:*", "accept 0.0.0:*", "accept 0.0.0.:*",
    "accept 0.0.0.a:*", "accept 127.0.0.1/-1:*", "accept 127.0.0.1/33:*",
    "accept [fe80:0000:0000:0000:0202:b3ff:fe1e:8329]:*", "accept [FE80::0202:b3ff:fe1e:8329]:*",
    "accept [0000:0000:0000:0000:0000:0000:0000:0000]/0:*", "accept [::]:*",
    "accept fe80::0202:b3ff:fe1e:8329:*", "accept [fe80::0202:b3ff:fe1e:8329:*",
    "accept fe80::0202:b3ff:fe1e:8329]:*", "accept [fe80::0202:b3ff:fe1e:832g]:*",
    "accept [fe80:::b3ff:fe1e:8329]:*", "accept [fe80::b3ff::fe1e:8329]:*",
    "accept [fe80::0202:b3ff:fe1e:8329]/-1:*", "accept [fe80::0202:b3ff:fe1e:8329]/129:*",
    "accept 127.0.0.1:0", "accept 127.0.0.1:1", "accept 127.0.0.1:65536", "accept 127.0.0.1:a",
    "accept 127.0.0.1:5-3", "accept 127.0.0.1:5-", "accept 127.0.0.1:-3", "accept 255.255.255.255/0:*",
    "accept 192.168.0.50/24:*", "accept 0.0.0.0:*", "accept 127.0.0.1/32:*", "accept *:80 ",
    "accept  *:80", "accept *: 80", "accept * :80", "accept *:80,443", "accept 1.2.3.4/255.255.255.0:*",
    "accept 1.2.3.4/255.0.255.0:*", "accept 1.2.3.4/1.2.3.4:*", "accept 1.2.3.4/024:*",
    "accept 1.2.3.4:080", "accept 1.2.3.4:+80", "accept 1.2.3.4:80\n", "ACCEPT *:*", "Accept *:*",
    "accept *:*\n", "accept\x00 *:*", "accept *:65535", "accept *:0-65535", "accept 1.2.3.4:1-65535",
    "accept6 1.2.3.4:*", "accept6 [::1]:*", "accept6 *:80", "reject6 [::]/64:*",
]

PROBES = [
    ("192.168.0.1", 80), ("10.0.0.1", 443), ("127.0.0.1", 1), ("8.8.8.8", 65535), ("0.0.0.0", 80),
    ("255.255.255.255", 80), ("87.0.0.5", 80), ("156.5.38.3", 80), ("156.5.38.3", 81),
    ("::1", 80), ("FE80:0000:0000:0000:0202:B3FF:FE1E:8329", 80), ("[FE80:0000:0000:0000:0202:B3FF:FE1E:8329]", 80),
    ("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 80), (None, 80), ("1.2.3.4", None), (None, None),
    ("192.168.0.1", None), ("1.2.3.4", 0), ("1.2.3.4", 65535), ("1.2.3.4", 100),
]

POLICIES = [
    ["accept *:80", "reject *:*"],
    ["reject *:25", "accept *:*"],
    ["accept 127.0.0.1:80", "reject *:*"],
    ["reject *:*"],
    ["accept *:*"],
    [],
    ["accept *:80-443", "accept 1.2.3.4:25", "reject *:*"],
    ["reject 10.0.0.0/8:*", "reject 127.0.0.1:*", "accept *:*"],
    ["accept6 *:80", "reject6 *:*", "accept *:25", "reject *:*"],
    ["reject 0.0.0.0/8:*", "reject 169.254.0.0/16:*", "reject 127.0.0.0/8:*", "reject 192.168.0.0/16:*",
     "reject 10.0.0.0/8:*", "reject 172.16.0.0/12:*", "reject 1.2.3.4:*", "reject *:25", "accept *:80", "accept *:443", "reject *:*"],
    ["accept *:20-23", "accept *:43", "accept *:53", "accept *:79-81", "accept *:88", "accept *:110", "accept *:143",
     "accept *:194", "accept *:220", "accept *:389", "accept *:443", "accept *:464", "accept *:531", "accept *:543-544",
     "accept *:554", "accept *:563", "accept *:636", "accept *:706", "accept *:749", "accept *:873", "accept *:902-904",
     "accept *:981", "accept *:989-995", "accept *:1194", "accept *:1220", "accept *:1293", "accept *:1500", "accept *:1533",
     "accept *:1677", "accept *:1723", "accept *:1755", "accept *:1863", "accept *:2082", "accept *:2083", "accept *:2086-2087",
     "accept *:2095-2096", "accept *:2102-2104", "accept *:3128", "accept *:3389", "accept *:3690", "accept *:4321", "accept *:4643",
     "accept *:5050", "accept *:5190", "accept *:5222-5223", "accept *:5228", "accept *:5900", "accept *:6660-6669", "accept *:6679",
     "accept *:6697", "accept *:8000", "accept *:8008", "accept *:8074", "accept *:8080", "accept *:8087-8088", "accept *:8332-8333",
     "accept *:8443", "accept *:8888", "accept *:9418", "accept *:9999", "accept *:10000", "accept *:11371", "accept *:19294",
     "accept *:19638", "accept *:50002", "accept *:64738", "reject *:*"],
]

MICRO_POLICIES = [
    "accept 80,443", "reject 1-65535", "accept 1-65535", "accept 80,443,", "accept", "reject 80-",
    "accept      80,443", "accept 80, 443", "accept 443-80", "accept 0", "accept 65536", "accept 80-80",
    "accept 1-1024,8080", "reject 22,25,1000-2000", "allow 80", "accept 80\n", "accept 80,,443",
    "accept 1,2,3,4,5,6,7,8,9,10", "ACCEPT 80", " accept 80", "accept 80 ", "accept a", "accept 80-a",
    "accept -80", "accept 80-443-500", "accept 0-1",
]

MICRO_PROBES = [("1.2.3.4", 80), ("1.2.3.4", 443), ("1.2.3.4", 22), ("1.2.3.4", 1), ("1.2.3.4", 65535),
                ("1.2.3.4", 1500), ("1.2.3.4", 8080), (None, 80), ("1.2.3.4", None), (None, None)]

CONFIG_POLICIES = [
    ("accept *:80, reject *:*", None), ("reject *:25", None), ("accept *:80,accept *:443,reject *:*", "1.2.3.4"),
    ("reject private:*, accept *:*", "10.0.0.5"), ("accept *:*", None), ("reject *:*", "bad"),
    ("accept 1.2.3.4:80", None), ("", None), ("accept6 *:*", None), ("accept *:80-", None),
    ("reject private:25", None), ("accept *:80, , reject *:*", None), ("accept *:80,reject *:*,", None),
    ("accept *:*,reject *:*", "1.2.3.4"),
]


def attempt(function, *args):
    try:
        return {"args": list(args), "result": function(*args), "error": False}
    except Exception:
        return {"args": list(args), "result": None, "error": True}


def mask_for_rule(value):
    return None if value is None else str(value)


def describe_rule(text):
    try:
        rule = stem.exit_policy.ExitPolicyRule(text)
    except Exception:
        return {"args": [text], "result": None, "error": True}
    matches = []
    for probe in PROBES:
        try:
            matches.append(bool(rule.is_match(*probe)))
        except Exception:
            matches.append(None)
    return {
        "args": [text],
        "error": False,
        "result": {
            "is_accept": rule.is_accept,
            "str": str(rule),
            "address": rule.address,
            "type": str(rule.get_address_type()),
            "mask": rule.get_mask(),
            "masked_bits": rule.get_masked_bits(),
            "min_port": rule.min_port,
            "max_port": rule.max_port,
            "address_wildcard": rule.is_address_wildcard(),
            "port_wildcard": rule.is_port_wildcard(),
            "is_private": rule.is_private(),
            "is_default": rule.is_default(),
            "matches": matches,
        },
    }


def describe_policy(rules):
    try:
        policy = stem.exit_policy.ExitPolicy(*rules)
    except Exception:
        return {"args": [rules], "result": None, "error": True}
    probes = []
    for probe in PROBES:
        try:
            probes.append(bool(policy.can_exit_to(*probe)))
        except Exception:
            probes.append(None)
    result = {
        "str": str(policy),
        "summary": policy.summary(),
        "is_exiting_allowed": policy.is_exiting_allowed(),
        "has_private": policy.has_private(),
        "stripped_private": str(policy.strip_private()),
        "has_default": policy.has_default(),
        "stripped_default": str(policy.strip_default()),
        "rule_count": len(list(policy)),
        "can_exit_to": probes,
    }
    return {"args": [rules], "result": result, "error": False}


def describe_micro_policy(text):
    try:
        policy = stem.exit_policy.MicroExitPolicy(text)
    except Exception:
        return {"args": [text], "result": None, "error": True}
    probes = []
    for probe in MICRO_PROBES:
        try:
            probes.append(bool(policy.can_exit_to(*probe)))
        except Exception:
            probes.append(None)
    return {"args": [text], "error": False, "result": {"str": str(policy), "can_exit_to": probes}}


def describe_config_policy(rules, address):
    try:
        policy = stem.exit_policy.get_config_policy(rules, address)
    except Exception:
        return {"args": [rules, address], "result": None, "error": True}
    return {"args": [rules, address], "error": False, "result": str(policy)}


def describe_version(text):
    try:
        version = stem.version.Version(text)
    except Exception:
        return {"args": [text], "result": None, "error": True}
    return {
        "args": [text],
        "error": False,
        "result": {
            "str": str(version),
            "major": version.major,
            "minor": version.minor,
            "micro": version.micro,
            "patch": version.patch,
            "status": version.status,
            "extra": version.extra,
            "git_commit": version.git_commit,
        },
    }


def version_order(left, right):
    try:
        a, b = stem.version.Version(left), stem.version.Version(right)
    except Exception:
        return None
    return {"args": [left, right], "error": False, "result": [a < b, a == b, a > b, a <= b, a >= b]}


def requirement_checks():
    results = []
    for name in stem.version.Requirement.keys():
        requirement = getattr(stem.version.Requirement, name)
        for text in VERSIONS:
            try:
                version = stem.version.Version(text)
            except Exception:
                continue
            results.append({"args": [name, text], "error": False, "result": version >= requirement})
    return results


def identity_keys():
    keys = []
    for index in range(6):
        seed = hashlib.sha256(b"identity %d" % index).digest()
        private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        keys.append(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
    return keys


def hidden_service_checks(output):
    service = hidden_service.HiddenServiceDescriptorV3
    keys = identity_keys()
    nonces = [hashlib.sha256(b"nonce %d" % index).digest() for index in range(4)]
    output["onion_address"] = []
    for key in keys:
        for suffix in (True, False):
            output["onion_address"].append(
                {"args": [key.hex(), suffix], "error": False, "result": service.address_from_identity_key(key, suffix)}
            )
    addresses = [service.address_from_identity_key(key) for key in keys]
    addresses += [addresses[0][:-6] + "a.onion", "a" * 56, "A" * 56 + ".onion", "short.onion", addresses[1].replace("a", "b", 1)]
    output["identity_key"] = []
    for address in addresses:
        try:
            result = service.identity_key_from_address(address).hex()
            output["identity_key"].append({"args": [address], "error": False, "result": result})
        except Exception:
            output["identity_key"].append({"args": [address], "error": True, "result": None})
    output["blinded_pubkey"] = []
    output["subcredential"] = []
    for key in keys:
        for nonce in nonces:
            blinded = hidden_service._blinded_pubkey(key, nonce)
            output["blinded_pubkey"].append({"args": [key.hex(), nonce.hex()], "error": False, "result": blinded.hex()})
            output["subcredential"].append(
                {"args": [key.hex(), blinded.hex()], "error": False, "result": service._subcredential(key, blinded).hex()}
            )


def timestamp_text(function, value):
    try:
        return {"args": [value], "result": function(value).strftime("%Y-%m-%d %H:%M:%S.%f"), "error": False}
    except Exception:
        return {"args": [value], "result": None, "error": True}


def crop_case(message, size, min_word_length, min_crop, ending, remainder):
    ending_value = stem.util.str_tools.Ending.ELLIPSE if ending == "ellipsis" else stem.util.str_tools.Ending.HYPHEN
    try:
        result = stem.util.str_tools.crop(message, size, min_word_length, min_crop, ending_value, remainder)
        return {"args": [message, size, min_word_length, min_crop, ending, remainder],
                "result": list(result) if remainder else result, "error": False}
    except Exception:
        return {"args": [message, size, min_word_length, min_crop, ending, remainder], "result": None, "error": True}


def main():
    c = stem.util.connection
    t = stem.util.tor_tools
    s = stem.util.str_tools
    output = {"rule_probes": PROBES, "micro_probes": MICRO_PROBES}
    output["is_valid_ipv4_address"] = [attempt(c.is_valid_ipv4_address, v) for v in IPV4]
    output["is_valid_ipv6_address"] = [
        attempt(c.is_valid_ipv6_address, v, brackets) for v in IPV6 for brackets in (False, True)
    ]
    output["is_valid_port"] = [attempt(c.is_valid_port, v, zero) for v in PORTS for zero in (False, True)]
    output["is_private_address"] = [attempt(c.is_private_address, v) for v in PRIVATE]
    output["expand_ipv6_address"] = [attempt(c.expand_ipv6_address, v) for v in EXPAND]
    output["get_mask_ipv4"] = [attempt(c.get_mask_ipv4, v) for v in range(-2, 36)]
    output["get_mask_ipv6"] = [attempt(c.get_mask_ipv6, v) for v in list(range(-2, 4)) + [31, 32, 33, 63, 64, 65, 127, 128, 129, 130]]
    output["masked_bits"] = [attempt(c._get_masked_bits, v) for v in MASKS]
    output["port_usage"] = [attempt(c.port_usage, v) for v in (0, 1, 22, 25, 53, 80, 443, 3306, 5222, 6667, 8080, 9050, 9051, 9150, 65535, 20, 119, 1194)]
    output["is_valid_fingerprint"] = [attempt(t.is_valid_fingerprint, v, prefix) for v in FINGERPRINTS for prefix in (False, True)]
    output["is_valid_nickname"] = [attempt(t.is_valid_nickname, v) for v in NICKNAMES]
    output["is_valid_circuit_id"] = [attempt(t.is_valid_circuit_id, v) for v in IDS]
    output["is_valid_stream_id"] = [attempt(t.is_valid_stream_id, v) for v in IDS]
    output["is_valid_connection_id"] = [attempt(t.is_valid_connection_id, v) for v in IDS]
    output["is_valid_hidden_service_address"] = [
        attempt(t.is_valid_hidden_service_address, v, version) for v in ONIONS for version in (None, 2, 3)
    ]
    output["size_label"] = [
        attempt(s.size_label, v, decimal, is_long, is_bytes, rounded)
        for v in SIZES for decimal in (0, 1, 2) for is_long in (False, True)
        for is_bytes in (True, False) for rounded in (False, True)
    ]
    output["time_label"] = [attempt(s.time_label, v, decimal, is_long) for v in TIMES for decimal in (0, 1, 2) for is_long in (False, True)]
    output["time_labels"] = [attempt(s.time_labels, int(v), is_long) for v in TIMES for is_long in (False, True)]
    output["short_time_label"] = [attempt(s.short_time_label, int(v)) for v in TIMES + [100000, 604800, 31536000, 3661]]
    output["parse_short_time_label"] = [attempt(s.parse_short_time_label, v) for v in SHORT_LABELS]
    output["parse_timestamp"] = [timestamp_text(s._parse_timestamp, v) for v in TIMESTAMPS]
    output["parse_iso_timestamp"] = [timestamp_text(s._parse_iso_timestamp, v) for v in ISO_TIMESTAMPS]
    output["to_camel_case"] = [attempt(s._to_camel_case, *v) for v in CAMEL]
    output["split_by_length"] = [attempt(s._split_by_length, *v) for v in SPLITS]
    output["crop"] = [
        crop_case(message, size, min_word, min_crop, ending, remainder)
        for message in CROP_MESSAGES for size in range(0, 26)
        for min_word in (4, None, 1) for min_crop in (0, 3)
        for ending in ("ellipsis", "hyphen") for remainder in (False, True)
    ]
    output["version"] = [describe_version(v) for v in VERSIONS]
    output["version_order"] = [
        entry for entry in (version_order(a, b) for a, b in itertools.product(VERSIONS, VERSIONS)) if entry
    ]
    output["requirement"] = requirement_checks()
    hidden_service_checks(output)
    output["exit_policy_rule"] = [describe_rule(v) for v in RULES]
    output["exit_policy"] = [describe_policy(v) for v in POLICIES]
    output["micro_exit_policy"] = [describe_micro_policy(v) for v in MICRO_POLICIES]
    output["config_policy"] = [describe_config_policy(*v) for v in CONFIG_POLICIES]
    json.dump(output, sys.stdout, separators=(",", ":"), sort_keys=True)


main()
