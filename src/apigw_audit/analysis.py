"""API gateway deployment configuration rules. Findings are review priorities from offline config data, not a security verdict."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .model import Gateway

SEV = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


def analyze(gw: Gateway) -> list[Finding]:
    out: list[Finding] = []
    for dep in gw.deployments:
        dsub = f"deployment:{gw.name}{dep.path_prefix}"
        if not dep.logging:
            out.append(Finding("AG005", "medium", dsub,
                               "Logging is disabled for this deployment; there is no access or execution trail "
                               "to investigate abuse or debug failures.", {}))
        for r in dep.routes:
            sub = f"route:{gw.name}{dep.path_prefix}{r.path}"
            if gw.endpoint_type == "PUBLIC" and r.auth == "NONE":
                out.append(Finding("AG001", "high", sub,
                                   "Route on a public gateway has no authentication; anyone on the internet "
                                   "can invoke it.", {"methods": r.methods}))
            if r.cors_allow_credentials and "*" in r.cors_origins:
                out.append(Finding("AG002", "high", sub,
                                   "CORS allows credentials from any origin ('*'); credentialed cross-origin "
                                   "requests from arbitrary sites are a browser-blocking misconfiguration and a leak risk.", {}))
            elif "*" in r.cors_origins:
                out.append(Finding("AG006", "medium", sub,
                                   "CORS allows any origin ('*'); any website can call this route from a visitor's browser.", {}))
            if r.backend.protocol == "http":
                out.append(Finding("AG003", "high", sub,
                                   "Backend protocol is plain http; traffic between the gateway and the backend "
                                   "is unencrypted and can be read or altered on the network path.", {}))
            if r.rate_limit_rps is None:
                out.append(Finding("AG004", "medium", sub,
                                   "Route has no rate limit; a single client can drive unlimited request volume "
                                   "against the backend.", {}))
            if r.quota_per_day is None:
                out.append(Finding("AG010", "medium", sub,
                                   "Route has no usage quota; there is no ceiling on total daily consumption.", {}))
            if not r.request_validation:
                out.append(Finding("AG007", "low", sub,
                                   "Request validation is off; unvalidated payloads reach the backend, which "
                                   "must do all input checking itself.", {}))
            if len(r.methods) > 5:
                out.append(Finding("AG008", "low", sub,
                                   f"Route allows {len(r.methods)} HTTP methods; broad method sets are rarely "
                                   "intended and widen the attack surface.", {"methods": r.methods}))
            if "*" in r.path:
                out.append(Finding("AG009", "low", sub,
                                   f"Route path {r.path!r} contains a wildcard and matches broadly; check the "
                                   "coverage is intended.", {}))
    out.sort(key=lambda f: (SEV[f.severity], f.rule, f.subject, f.message))
    return out
