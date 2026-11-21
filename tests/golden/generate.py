import datetime
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import stem.descriptor
from stem.descriptor import DocumentHandler

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "descriptor")

CASES = [
    ("bandwidth_file_v1.0", "bandwidth-file 1.0", "entries"),
    ("bandwidth_file_v1.2", "bandwidth-file 1.2", "entries"),
    ("bandwidth_file_v1.4", "bandwidth-file 1.4", "entries"),
    ("bridge_descriptor", None, "entries"),
    ("bridge_descriptor_with_ed25519", None, "entries"),
    ("bridge_extrainfo_descriptor_with_ed25519", None, "entries"),
    ("bridge_network_status", None, "document"),
    ("cached-certs", "dir-key-certificate-3 1.0", "entries"),
    ("cached-consensus", "network-status-consensus-3 1.0", "document"),
    ("cached-consensus-v2", None, "document"),
    ("cached-microdescs", None, "entries"),
    ("compressed_bz2", "network-status-consensus-3 1.0", "entries"),
    ("compressed_gzip", "network-status-consensus-3 1.0", "entries"),
    ("compressed_identity", "network-status-consensus-3 1.0", "entries"),
    ("compressed_lzma", "network-status-consensus-3 1.0", "entries"),
    ("compressed_zstd", "network-status-consensus-3 1.0", "entries"),
    ("cr_in_contact_line", None, "entries"),
    ("descriptor_archive.tar", None, "entries"),
    ("descriptor_archive.tar.bz2", None, "entries"),
    ("descriptor_archive.tar.gz", None, "entries"),
    ("detached_signatures", "detached-signature 1.0", "entries"),
    ("example_descriptor", None, "entries"),
    ("extrainfo_bridge_descriptor", None, "entries"),
    ("extrainfo_bridge_descriptor_multiple", None, "entries"),
    ("extrainfo_descriptor_with_ed25519", None, "entries"),
    ("extrainfo_relay_descriptor", None, "entries"),
    ("hidden_service_basic_auth", None, "entries"),
    ("hidden_service_duckduckgo", None, "entries"),
    ("hidden_service_facebook", None, "entries"),
    ("hidden_service_stealth_auth", None, "entries"),
    ("hidden_service_v3", "hidden-service-descriptor-3 1.0", "entries"),
    ("metrics_cert", None, "entries"),
    ("metrics_consensus", None, "document"),
    ("metrics_server_desc_multiple", None, "entries"),
    ("metrics_vote", None, "document"),
    ("negative_uptime", None, "entries"),
    ("non-ascii_descriptor", None, "entries"),
    ("old_descriptor", None, "entries"),
    ("server_descriptor_with_ed25519", None, "entries"),
    ("collector/bandwidths-2019-05-cropped.tar", None, "entries"),
    ("collector/bridge-extra-infos-2019-03-cropped.tar", None, "entries"),
    ("collector/bridge-server-descriptors-2019-02-cropped.tar", None, "entries"),
    ("collector/bridge-statuses-2019-05-cropped.tar", None, "entries"),
    ("collector/certs-cropped.tar", None, "entries"),
    ("collector/consensuses-2018-06-cropped.tar", None, "document"),
    ("collector/exit-list-2018-11-cropped.tar", None, "entries"),
    ("collector/extra-infos-2019-04-cropped.tar", None, "entries"),
    ("collector/microdescs-2019-05-cropped.tar", None, "entries"),
    ("collector/server-descriptors-2005-12-cropped.tar", None, "entries"),
]

SAMPLE = 25
BINARY_ATTRIBUTES = {"key", "signature", "data"}
STRING_TYPES = {"Version", "ExitPolicy", "MicroExitPolicy"}

HANDLERS = {
    "entries": DocumentHandler.ENTRIES,
    "document": DocumentHandler.DOCUMENT,
}


def dump(value, depth=0):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (set, frozenset)):
        return sorted((dump(item, depth + 1) for item in value), key=json.dumps)
    if isinstance(value, (list, tuple)):
        return [dump(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {str(key): dump(item, depth + 1) for key, item in value.items()}
    if type(value).__name__ in STRING_TYPES:
        return str(value)
    if depth > 6:
        return str(value)
    attributes = getattr(value, "__dict__", None)
    if attributes is not None and not type(value).__name__.startswith("Exit"):
        result = {
            name: dump_attribute(name, item, depth)
            for name, item in attributes.items()
            if not name.startswith("_") and name != "document"
        }
        result["__class__"] = type(value).__name__
        return result
    return str(value)


def dump_attribute(name, item, depth):
    if isinstance(item, bytes) and name in BINARY_ATTRIBUTES:
        return item.hex()
    return dump(item, depth + 1)


def run_case(name, descriptor_type, handler):
    path = os.path.join(DATA, name)
    for validate in (True, False):
        try:
            descriptors = list(
                stem.descriptor.parse_file(
                    path,
                    descriptor_type,
                    validate=validate,
                    document_handler=HANDLERS[handler],
                )
            )
        except Exception as exc:
            error = "%s: %s" % (type(exc).__name__, str(exc)[:200])
            if validate:
                continue
            return {"validate": None, "error": error, "descriptors": []}
        return {
            "validate": validate,
            "error": None,
            "total": len(descriptors),
            "descriptors": [dump(descriptor) for descriptor in descriptors[:SAMPLE]],
        }


def dump_file(path, limit, descriptor_type):
    descriptors = stem.descriptor.parse_file(
        path,
        descriptor_type,
        validate=True,
        document_handler=DocumentHandler.DOCUMENT,
    )
    output = []
    for index, descriptor in enumerate(descriptors):
        if index >= limit:
            break
        output.append(dump(descriptor))
    json.dump(output, sys.stdout)


def main():
    if len(sys.argv) > 1:
        descriptor_type = sys.argv[3] if len(sys.argv) > 3 else None
        dump_file(sys.argv[1], int(sys.argv[2]), descriptor_type)
        return
    output = {}
    for name, descriptor_type, handler in CASES:
        result = run_case(name, descriptor_type, handler)
        result["descriptor_type"] = descriptor_type
        result["handler"] = handler
        output[name] = result
    json.dump(output, sys.stdout, indent=1, sort_keys=True)


main()
