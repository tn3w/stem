import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import urllib.request

import stem.directory

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


class Response:
    def __init__(self, content):
        self.content = content

    def read(self):
        return self.content


def serve(content):
    urllib.request.urlopen = lambda url, timeout=None: Response(content)


def describe(directory):
    entry = {
        "address": directory.address,
        "or_port": directory.or_port,
        "dir_port": directory.dir_port,
        "fingerprint": directory.fingerprint,
        "nickname": directory.nickname,
        "orport_v6": list(directory.orport_v6) if directory.orport_v6 else None,
    }
    if hasattr(directory, "v3ident"):
        entry["v3ident"] = directory.v3ident
        entry["is_bandwidth_authority"] = directory.is_bandwidth_authority
    if hasattr(directory, "has_extrainfo"):
        entry["has_extrainfo"] = directory.has_extrainfo
        entry["header"] = dict(directory.header)
    return entry


def main():
    output = {}
    with open(os.path.join(ROOT, "src/data/auth_dirs.inc"), "rb") as handle:
        serve(handle.read())
    output["authorities"] = {
        name: describe(directory)
        for name, directory in stem.directory.Authority.from_remote().items()
    }
    with open(os.path.join(ROOT, "src/data/fallback_dirs.inc"), "rb") as handle:
        serve(handle.read())
    output["fallbacks"] = {
        name: describe(directory)
        for name, directory in stem.directory.Fallback.from_remote().items()
    }
    output["cached_fallbacks"] = {
        name: describe(directory)
        for name, directory in stem.directory.Fallback.from_cache(
            os.path.join(ROOT, "tests/data/cached_fallbacks.cfg")
        ).items()
    }
    json.dump(output, sys.stdout, separators=(",", ":"), sort_keys=True)


main()
