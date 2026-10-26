"""Convert an OCI-style gateway + deployment export into this tool's simplified gateway JSON.

Accepted shapes: a top-level {"data": {...}} envelope (the shape of `oci api-gateway gateway get`
output with deployments embedded) or the unwrapped object. The object carries display-name,
endpoint-type and deployments; each deployment has path-prefix and a specification with
logging-policies and routes. Extra OCI fields are ignored. Reads a file you already have;
makes no API calls.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse


class ImportError(ValueError):
    pass


# OCI request authentication type -> this tool's auth value.
AUTH_MAP = {"JWT_AUTHENTICATION": "JWT", "CUSTOM_AUTHENTICATION": "FUNCTIONS"}


class _Lines:
    """Best-effort line lookup: remember which line each searched anchor first appears on,
    scanning forward so repeated anchors keep moving with the data."""

    def __init__(self, text):
        self.lines = text.splitlines()
        self.pos = 0

    def find(self, anchor):
        for i in range(self.pos, len(self.lines)):
            if anchor in self.lines[i]:
                self.pos = i + 1
                return i + 1
        return 1


def _daily_quota(spec):
    """First usage-plan quota with reset-period DAY -> requests/day, else None.

    OCI usage plans carry quota policies at the deployment level; WEEK/MONTH reset
    periods do not map onto this tool's daily quota field and stay unset on purpose
    (AG010 then flags the route, which is intended visibility)."""
    for plan in spec.get("usage-plans", []):
        q = (plan or {}).get("quota") or {}
        if q.get("reset-period") == "DAY" and isinstance(q.get("number-of-requests"), int):
            return q["number-of-requests"]
    return None


def _route(r, anchor, lines):
    """Map one OCI-style route. Returns (route_dict, error_or_None)."""
    if not isinstance(r, dict):
        return None, "route is not an object"
    path = r.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        return None, f"route path missing or invalid: {path!r}"
    backend = r.get("backend") or {}
    url = backend.get("url")
    scheme = urlparse(url if isinstance(url, str) else "").scheme
    if scheme not in ("http", "https"):
        return None, f"backend url missing or has no http(s) scheme: {url!r}"
    pol = r.get("request-policies") or {}
    auth_pol = pol.get("authentication") or {}
    auth = AUTH_MAP.get(auth_pol.get("type"), "NONE")
    cors_pol = pol.get("cors") or {}
    rl = (pol.get("rate-limiting") or {}).get("rate-in-requests-per-second")
    bv = pol.get("body-validation") or {}
    route = {
        "path": path,
        "methods": r.get("methods", ["GET"]),
        "auth": auth,
        "cors": {
            "allowed_origins": cors_pol.get("allowed-origins", []),
            "allow_credentials": bool(cors_pol.get("is-allow-credentials-enabled", False)),
        },
        "rate_limit_rps": rl,
        "request_validation": bool(bv.get("required", False)),
        "backend": {"protocol": scheme},
    }
    if route["rate_limit_rps"] is None:
        del route["rate_limit_rps"]
    return route, None


def convert(text: str) -> dict:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ImportError("top level must be an object (optionally a {\"data\": {...}} envelope)")
    data = data.get("data", data)
    if not isinstance(data, dict) or not isinstance(data.get("display-name"), str):
        raise ImportError("expected an object with a display-name")
    lines = _Lines(text)
    errors = []
    deployments = []
    for i, dep in enumerate(data.get("deployments", [])):
        where = f"deployments[{i}]"
        if not isinstance(dep, dict) or not isinstance(dep.get("path-prefix"), str):
            errors.append(f"{where}: deployment missing path-prefix")
            continue
        spec = dep.get("specification") or {}
        quota = _daily_quota(spec)
        lp = spec.get("logging-policies") or {}
        access = (lp.get("access-log") or {}).get("is-enabled", False)
        execution = (lp.get("execution-log") or {}).get("is-enabled", False)
        routes = []
        for j, r in enumerate(spec.get("routes", [])):
            anchor = r.get("path") if isinstance(r, dict) else ""
            if not anchor and isinstance(r, dict):
                anchor = (r.get("backend") or {}).get("url") or ""
            line = lines.find(f'"{anchor}"') if anchor else 1
            route, err = _route(r, anchor, lines)
            if err:
                errors.append(f"{where}.routes[{j}] (line {line}): {err}")
            else:
                if quota is not None:
                    route["quota_per_day"] = quota
                routes.append(route)
        deployments.append({"path_prefix": dep["path-prefix"],
                            "logging": bool(access or execution), "routes": routes})
    if errors:
        raise ImportError("cannot import:\n" + "\n".join(errors))
    return {"gateway": data["display-name"],
            "endpoint_type": (data.get("endpoint-type") or "PUBLIC").upper(),
            "deployments": deployments}


def load_export(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return convert(f.read())
