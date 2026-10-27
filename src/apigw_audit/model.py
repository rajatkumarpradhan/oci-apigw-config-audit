"""Load and validate an API gateway deployment export (this project's own schema, not the OCI API Gateway API shape).

One file holds a gateway, its endpoint type and its deployments with routes. The data is
expected to come from an export a user already has; the auditor makes no API calls.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


class ModelError(ValueError):
    pass


METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
AUTH = {"NONE", "JWT", "OAUTH2", "FUNCTIONS"}
ENDPOINTS = {"PUBLIC", "PRIVATE"}


@dataclass
class Backend:
    protocol: str = "https"   # http or https


@dataclass
class Route:
    path: str
    methods: list[str] = field(default_factory=list)
    auth: str = "NONE"
    audience: str | None = None
    cors_origins: list[str] = field(default_factory=list)
    cors_allow_credentials: bool = False
    rate_limit_rps: float | None = None
    quota_per_day: int | None = None
    request_validation: bool = False
    backend: Backend = field(default_factory=Backend)


@dataclass
class Deployment:
    path_prefix: str
    logging: bool = True
    routes: list[Route] = field(default_factory=list)


@dataclass
class Gateway:
    name: str
    endpoint_type: str = "PUBLIC"
    deployments: list[Deployment] = field(default_factory=list)
    expected_audiences: list[str] = field(default_factory=list)


def _str(v, what):
    if not isinstance(v, str) or not v.strip():
        raise ModelError(f"{what} must be a non-empty string")
    return v


def _bool(v, what):
    if not isinstance(v, bool):
        raise ModelError(f"{what} must be true or false, got {v!r}")
    return v


def _path(v, what):
    v = _str(v, what)
    if not v.startswith("/"):
        raise ModelError(f"{what} must start with '/', got {v!r}")
    return v


def _num(v, what, lo, hi, integer):
    if isinstance(v, bool) or not isinstance(v, int if integer else (int, float)) or not lo <= v <= hi:
        raise ModelError(f"{what} must be a number in [{lo}, {hi}], got {v!r}")
    return v


def _route(d, what):
    if not isinstance(d, dict):
        raise ModelError(f"{what} must be an object")
    methods = d.get("methods", [])
    if not isinstance(methods, list) or not methods:
        raise ModelError(f"{what}.methods must be a non-empty list")
    methods = [_str(m, f"{what}.methods[{i}]").upper() for i, m in enumerate(methods)]
    bad = [m for m in methods if m not in METHODS]
    if bad:
        raise ModelError(f"{what}.methods has unsupported method(s): {bad!r}")
    auth = _str(d.get("auth", "NONE"), f"{what}.auth").upper()
    if auth not in AUTH:
        raise ModelError(f"{what}.auth must be one of {sorted(AUTH)}, got {auth!r}")
    cors = d.get("cors", {})
    if not isinstance(cors, dict):
        raise ModelError(f"{what}.cors must be an object")
    origins = cors.get("allowed_origins", [])
    if not isinstance(origins, list):
        raise ModelError(f"{what}.cors.allowed_origins must be a list")
    origins = [_str(o, f"{what}.cors.allowed_origins[{i}]").strip() for i, o in enumerate(origins)]
    backend = d.get("backend", {})
    if not isinstance(backend, dict):
        raise ModelError(f"{what}.backend must be an object")
    proto = _str(backend.get("protocol", "https"), f"{what}.backend.protocol").lower()
    if proto not in ("http", "https"):
        raise ModelError(f"{what}.backend.protocol must be http or https, got {proto!r}")
    rl = d.get("rate_limit_rps")
    quota = d.get("quota_per_day")
    aud = d.get("audience")
    if aud is not None:
        aud = _str(aud, f"{what}.audience").strip()
    return Route(
        path=_path(d.get("path"), f"{what}.path"),
        methods=methods,
        auth=auth,
        audience=aud,
        cors_origins=origins,
        cors_allow_credentials=_bool(cors.get("allow_credentials", False),
                                     f"{what}.cors.allow_credentials"),
        rate_limit_rps=None if rl is None else _num(rl, f"{what}.rate_limit_rps", 0.001, 1e9, False),
        quota_per_day=None if quota is None else int(_num(quota, f"{what}.quota_per_day", 1, 10**12, True)),
        request_validation=_bool(d.get("request_validation", False), f"{what}.request_validation"),
        backend=Backend(proto),
    )


def load(data: dict) -> Gateway:
    try:
        name = _str(data.get("gateway"), "gateway").strip()
        etype = _str(data.get("endpoint_type", "PUBLIC"), "endpoint_type").upper()
        if etype not in ENDPOINTS:
            raise ModelError(f"endpoint_type must be one of {sorted(ENDPOINTS)}, got {etype!r}")
        deployments = []
        for i, dep in enumerate(data.get("deployments", [])):
            w = f"deployments[{i}]"
            if not isinstance(dep, dict):
                raise ModelError(f"{w} must be an object")
            deployments.append(Deployment(
                path_prefix=_path(dep.get("path_prefix"), f"{w}.path_prefix"),
                logging=_bool(dep.get("logging", True), f"{w}.logging"),
                routes=[_route(r, f"{w}.routes[{j}]") for j, r in enumerate(dep.get("routes", []))],
            ))
        cfg = data.get("config", {})
        if not isinstance(cfg, dict):
            raise ModelError("config must be an object")
        exp = cfg.get("expected_audiences", [])
        if not isinstance(exp, list):
            raise ModelError("config.expected_audiences must be a list")
        exp = [_str(a, f"config.expected_audiences[{i}]").strip()
               for i, a in enumerate(exp)]
    except (TypeError, AttributeError) as e:
        raise ModelError(f"invalid model: {e!r}") from e
    return Gateway(name, etype, deployments, exp)


def load_file(path: str) -> Gateway:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
