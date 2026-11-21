import ast
import datetime
import json
import sys
import warnings

warnings.filterwarnings("ignore")

import stem.response
import stem.response.events

SOURCE = sys.argv[1]


def dump(value, depth=0):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")
    if isinstance(value, (set, frozenset)):
        return sorted((dump(item, depth + 1) for item in value), key=json.dumps)
    if isinstance(value, (list, tuple)):
        return [dump(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {str(key): dump(item, depth + 1) for key, item in value.items()}
    attributes = getattr(value, "__dict__", None)
    if attributes is not None and depth < 5:
        return {
            name: dump(item, depth + 1)
            for name, item in attributes.items()
            if not name.startswith("_") and name not in ("arrived_at",)
        }
    return str(value)


def corpus():
    tree = ast.parse(open(SOURCE).read())
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if text.startswith("650") and len(text) > 5:
                found.append(text)
    return sorted(set(found))


def evaluate(text):
    try:
        message = stem.response.ControlMessage.from_str(text, "EVENT", normalize=True)
        event = dump(message)
        return {"content": text, "error": False, "event": event, "type": message.type}
    except Exception:
        return {"content": text, "error": True, "event": None, "type": None}


def mutants(text):
    if "\n" in text.strip("\r\n"):
        return []
    tokens = text.strip("\r\n").split(" ")
    results = []
    for index in range(1, len(tokens)):
        token = tokens[index]
        variants = [
            tokens[:index] + tokens[index + 1:],
            tokens[:index + 1] + tokens[index:],
            tokens[:index] + [token + "=x"] + tokens[index + 1:],
            tokens[:index] + [token.split("=")[0] + "=bogus" if "=" in token else "bogus"] + tokens[index + 1:],
            tokens[:index] + [""] + tokens[index + 1:],
            tokens[:index] + [token.upper() if token.islower() else token.lower()] + tokens[index + 1:],
        ]
        for variant in variants:
            results.append(" ".join(variant) + "\r\n")
    return results


def main():
    output = []
    for text in corpus():
        result = evaluate(text)
        output.append(result)
        if not result["error"]:
            output.extend(evaluate(mutant) for mutant in mutants(text))
    json.dump(output, sys.stdout, separators=(",", ":"))


main()
