from __future__ import annotations

import argparse
import json
import sys

from . import analysis, importer, model

DISCLAIMER = ("Review priorities from offline API gateway configuration data. No API calls are made and nothing is "
              "verified against a live gateway or cloud provider; a clean result is not a security certification.")


def _import_main(argv) -> int:
    ap = argparse.ArgumentParser(prog="apigw-audit import",
                                 description="Convert an OCI-style gateway export into the simplified gateway JSON. "
                                             "Reads a file you already have; makes no API calls.")
    ap.add_argument("export")
    ap.add_argument("--output", "-o", help="write the gateway JSON here (default stdout)")
    a = ap.parse_args(argv)
    try:
        gw = importer.load_export(a.export)
    except (OSError, json.JSONDecodeError, importer.ImportError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    out = json.dumps(gw, indent=1) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        n = sum(len(d["routes"]) for d in gw["deployments"])
        print(f"wrote {n} route(s) across {len(gw['deployments'])} deployment(s) to {a.output}", file=sys.stderr)
    else:
        sys.stdout.write(out)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["import"]:
        return _import_main(argv[1:])
    ap = argparse.ArgumentParser(prog="apigw-audit",
                                 description="Offline API gateway deployment configuration audit (synthetic/exported data).")
    ap.add_argument("gateway")
    ap.add_argument("--output")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(argv)
    try:
        gw = model.load_file(a.gateway)
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = analysis.analyze(gw)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    n_routes = sum(len(d.routes) for d in gw.deployments)
    print(f"{len(fs)} finding(s) across {n_routes} route(s) in gateway {gw.name}.")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump({"disclaimer": DISCLAIMER, "gateway": gw.name,
                       "findings": [f.to_dict() for f in fs]}, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
