from __future__ import annotations

import argparse
import json
import sys

from . import analysis, model

DISCLAIMER = ("Review priorities from offline API gateway configuration data. No API calls are made and nothing is "
              "verified against a live gateway or cloud provider; a clean result is not a security certification.")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
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
