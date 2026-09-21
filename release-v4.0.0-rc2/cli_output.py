"""Stable process-level output contract for the ACSD command line."""

import json


EXIT_OK = 0
EXIT_VERIFY_FAIL = 1
EXIT_USAGE = 2
EXIT_STATE_CONFLICT = 3
EXIT_EXTERNAL = 4
EXIT_INCOMPLETE = 5


def emit_json(command, code, message, data):
    print(json.dumps({
        "command": command,
        "status": "ok" if code == EXIT_OK else "error",
        "exit_code": code,
        "message": message,
        "data": data,
    }, ensure_ascii=False))


def emit_human(command, code, message, data):
    print(f"{command}: {message} (exit {code})")
    for key, value in data.items():
        print(f"  {key}: {value}")
