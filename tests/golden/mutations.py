import io
import signal
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import stem.descriptor
from stem.descriptor import DocumentHandler

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "descriptor")

BASES = [
    ("example_descriptor", "server-descriptor 1.0", "entries"),
    ("server_descriptor_with_ed25519", "server-descriptor 1.0", "entries"),
    ("bridge_descriptor", "bridge-server-descriptor 1.0", "entries"),
    ("extrainfo_relay_descriptor", "extra-info 1.0", "entries"),
    ("extrainfo_descriptor_with_ed25519", "extra-info 1.0", "entries"),
    ("extrainfo_bridge_descriptor", "bridge-extra-info 1.0", "entries"),
    ("cached-microdescs", "microdescriptor 1.0", "entries"),
    ("metrics_consensus", "network-status-consensus-3 1.0", "document"),
    ("metrics_vote", "network-status-vote-3 1.0", "document"),
    ("cached-consensus-v2", "network-status-2 1.0", "document"),
    ("bridge_network_status", "bridge-network-status 1.0", "document"),
    ("metrics_cert", "dir-key-certificate-3 1.0", "entries"),
    ("hidden_service_basic_auth", "hidden-service-descriptor 1.0", "entries"),
    ("hidden_service_v3", "hidden-service-descriptor-3 1.0", "entries"),
    ("bandwidth_file_v1.2", "bandwidth-file 1.2", "entries"),
]

OPERATIONS = [
    "delete",
    "duplicate",
    "append_junk",
    "keyword_only",
    "blank",
    "swap_with_next",
]

HANDLERS = {
    "entries": DocumentHandler.ENTRIES,
    "document": DocumentHandler.DOCUMENT,
}


def mutate(lines, operation, index):
    lines = list(lines)
    line = lines[index]
    if operation == "delete":
        del lines[index]
    elif operation == "duplicate":
        lines.insert(index, line)
    elif operation == "append_junk":
        lines[index] = line + " junk"
    elif operation == "keyword_only":
        lines[index] = line.split(" ")[0]
    elif operation == "blank":
        lines[index] = ""
    elif operation == "swap_with_next":
        if index + 1 >= len(lines):
            return None
        lines[index], lines[index + 1] = lines[index + 1], lines[index]
    return lines


class Timeout(Exception):
    pass


def on_alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, on_alarm)


def accepted(content, descriptor_type, handler):
    signal.alarm(5)
    try:
        descriptors = stem.descriptor.parse_file(
            io.BytesIO(content),
            descriptor_type,
            validate=True,
            document_handler=HANDLERS[handler],
        )
        for _ in descriptors:
            pass
        return True
    except Timeout:
        return None
    except Exception:
        return False
    finally:
        signal.alarm(0)


def main():
    cases = []
    for name, descriptor_type, handler in BASES:
        with open(os.path.join(DATA, name), "rb") as handle:
            original = handle.read().decode("utf-8")
        lines = original.split("\n")
        if not accepted(original.encode("utf-8"), descriptor_type, handler):
            raise SystemExit("base %s is rejected by python" % name)
        for operation in OPERATIONS:
            for index in range(len(lines)):
                mutated = mutate(lines, operation, index)
                if mutated is None:
                    continue
                content = "\n".join(mutated).encode("utf-8")
                result = accepted(content, descriptor_type, handler)
                if result is None:
                    continue
                cases.append(
                    {
                        "file": name,
                        "type": descriptor_type,
                        "handler": handler,
                        "operation": operation,
                        "index": index,
                        "accepted": result,
                    }
                )
    json.dump(cases, sys.stdout, separators=(",", ":"))


main()
