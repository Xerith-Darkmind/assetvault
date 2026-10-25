#!/usr/bin/env python3
"""Connector, import, review, and export commands. Prints JSON only.

    python bin/connect.py connectors
    python bin/connect.py entra --config entra.json --test
    python bin/connect.py sync entra
    python bin/connect.py import devices.csv
    python bin/connect.py commit --review 1 --verify 0
    python bin/connect.py export pdf-redacted
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import avcore as av
import connectors
import ops
from connectors.base import ConnectorError
from errors import MergeError, OpsError

def emit(obj, code=0):
    sys.stdout.write(json.dumps(obj, indent=2, default=str) + "\n")
    raise SystemExit(code)

def fail(message, code=1):
    emit({"ok": False, "error": av.scrub(str(message))}, code)

def load_json_arg(spec, label):
    spec = (spec or "").strip()
    if not spec:
        raise OpsError(label + " is required")
    if spec.startswith("{"):
        try:
            data = json.loads(spec)
        except json.JSONDecodeError:
            raise OpsError(label + " must be an object") from None
    else:
        if not os.path.isfile(spec):
            raise OpsError(label + " file not found")
        try:
            with open(spec, encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError:
            raise OpsError(label + " must be an object") from None
    if not isinstance(data, dict):
        raise OpsError(label + " must be an object")
    return data

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in connectors.CLASSES and (len(argv) == 1 or str(argv[1]).startswith("-")):
        argv = ["connect", *argv]
    parser = argparse.ArgumentParser(prog="assetvault.connect", add_help=True)
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("connectors")
    sub.add_parser("reviews")
    sub.add_parser("help")
    connect = sub.add_parser("connect")
    connect.add_argument("name")
    connect.add_argument("--config", required=True)
    connect.add_argument("--name", dest="display")
    connect.add_argument("--test", action="store_true")
    sync = sub.add_parser("sync")
    sync.add_argument("name")
    disconnect = sub.add_parser("disconnect")
    disconnect.add_argument("name")
    imported = sub.add_parser("import")
    imported.add_argument("file")
    imported.add_argument("--name")
    imported.add_argument("--mapping")
    commit = sub.add_parser("commit")
    commit.add_argument("--review", type=int)
    commit.add_argument("--verify", type=int, action="append")
    discard = sub.add_parser("discard")
    discard.add_argument("--review", type=int)
    export = sub.add_parser("export")
    export.add_argument("kind")
    args = parser.parse_args(argv)
    if args.cmd in (None, "help"):
        emit({
            "ok": True,
            "version": ops.version_string(),
            "commands": ["connectors", "connect", "sync", "disconnect", "import", "commit", "discard", "export", "reviews"],
        })
    try:
        if args.cmd == "connectors":
            emit(ops.list_connectors())
        elif args.cmd == "reviews":
            emit(ops.list_reviews())
        elif args.cmd == "connect":
            emit(ops.connect_source(args.name, load_json_arg(args.config, "config"), preview=args.test, display_name=args.display))
        elif args.cmd == "sync":
            emit(ops.sync_source(args.name))
        elif args.cmd == "disconnect":
            emit(ops.disconnect_source(args.name))
        elif args.cmd == "import":
            mapping = load_json_arg(args.mapping, "mapping") if args.mapping else None
            emit(ops.import_file(args.file, name=args.name, mapping=mapping))
        elif args.cmd == "commit":
            emit(ops.commit_staged(args.review, verify=args.verify))
        elif args.cmd == "discard":
            emit(ops.discard_staged(args.review))
        elif args.cmd == "export":
            emit(ops.export_inventory(args.kind))
        else:
            fail("unknown command")
    except av.UnlockError:
        fail("unlock failed", 2)
    except (OpsError, MergeError, ConnectorError, ValueError) as exc:
        fail(str(exc), 1)
    except Exception:
        fail("command failed", 1)

if __name__ == "__main__":
    main()
