import io
import json
import signal
import sys
import warnings

warnings.filterwarnings("ignore")

import stem.descriptor
from stem.descriptor import DocumentHandler

HANDLERS = {"entries": DocumentHandler.ENTRIES, "document": DocumentHandler.DOCUMENT}


class Timeout(Exception):
    pass


def on_alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, on_alarm)


def accepted(case):
    signal.alarm(5)
    try:
        descriptors = stem.descriptor.parse_file(
            io.BytesIO(bytes.fromhex(case["hex"])),
            case["type"],
            validate=True,
            document_handler=HANDLERS[case["handler"]],
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


cases = json.load(sys.stdin)
json.dump([accepted(case) for case in cases], sys.stdout)
