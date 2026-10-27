# oci-apigw-config-audit

Offline API Gateway deployment configuration auditor. It reads one JSON file describing a gateway, its deployments and routes (an export you already have), applies 11 rules and prints findings by severity. It can also write a JSON report. An `import` subcommand converts an OCI-style gateway export into the gateway schema.

This project is a portfolio piece. It uses its own simplified schema (not the OCI API Gateway API shape), works only on synthetic or exported files, and has not been validated against a live OCI tenancy. Findings are review priorities from offline data, not a security verdict: the auditor makes no API calls and verifies nothing against a live gateway. A clean result is not a security certification.

## Install and run

```
pip install -e .
apigw-audit examples/good.json                     # clean example, no findings
apigw-audit examples/risky.json                    # intentionally bad example, triggers all 11 rules
apigw-audit gateway.json --output report.json      # JSON report with a disclaimer field
apigw-audit gateway.json --fail-on high            # exit 2 if any finding is high or worse
```

Exit codes: 0 ok, 1 bad input, 2 a finding at or above `--fail-on`.

## Import from an export

`apigw-audit import` converts an OCI-style gateway + deployment listing into this tool's gateway JSON, so a real export can be audited without rewriting it by hand. It reads a file you already have; it makes no API calls.

```
apigw-audit import examples/export.json                    # writes gateway JSON to stdout
apigw-audit import examples/export.json -o gateway.json
apigw-audit gateway.json
```

Accepted shape: an object with `display-name`, `endpoint-type` and `deployments`, optionally inside a `data` envelope (the shape of `oci api-gateway gateway get` output with deployments embedded). Each deployment needs `path-prefix` and a `specification` with `logging-policies` and `routes`; each route needs a `path` and a `backend.url` with an http(s) scheme. Extra OCI fields are ignored.

Mapping decisions, all documented here because they are simplifications:

- `request-policies.authentication.type` maps `JWT_AUTHENTICATION` -> `JWT` and `CUSTOM_AUTHENTICATION` -> `FUNCTIONS`; anything else or absent -> `NONE`.
- `rate-limiting.rate-in-requests-per-second` -> `rate_limit_rps`.
- Usage-plan quotas map only when `reset-period` is `DAY` (first matching plan wins, applied to every route in the deployment). WEEK/MONTH quotas stay unset on purpose, so AG010 can flag them.
- Logging is on when either the access or the execution log policy is enabled.
- `body-validation.required` -> `request_validation`.

Routes that cannot be mapped (missing path, backend url without an http(s) scheme, non-object rows) stop the import, and every bad route is reported as `deployments[i].routes[j]` with a best-effort line number (the line where that route's path or backend url appears; the row index is always exact).

## Input schema (simplified, project-specific)

```json
{
  "gateway": "payments-gw",
  "endpoint_type": "PUBLIC",
  "deployments": [
    {
      "path_prefix": "/pay",
      "logging": true,
      "routes": [
        {
          "path": "/charge",
          "methods": ["POST"],
          "auth": "JWT",
          "cors": {"allowed_origins": ["https://app.example.com"], "allow_credentials": false},
          "rate_limit_rps": 50,
          "quota_per_day": 100000,
          "request_validation": true,
          "backend": {"protocol": "https"}
        }
      ]
    }
  ]
}
```

- `endpoint_type` is `PUBLIC` (default) or `PRIVATE`.
- Optional `config.expected_audiences`: a list of audience strings the gateway expects. When non-empty, AG011 checks JWT/OAUTH2 routes against it (exact, case-insensitive). An empty or absent list disables the rule.
- `logging` on a deployment defaults to true; set it false to mark a deployment with no access/execution logs.
- Route `auth` is one of `NONE` (default), `JWT`, `OAUTH2`, `FUNCTIONS`.
- Optional route `audience`: the audience string a JWT/OAUTH2 route expects, checked against `config.expected_audiences` (AG011). Missing on an authenticated route is itself a finding when the rule is enabled.
- `cors.allowed_origins` defaults to empty; `cors.allow_credentials` defaults to false.
- `rate_limit_rps` and `quota_per_day` default to absent, which is itself a finding (AG004 / AG010).
- `request_validation` defaults to false, which is a finding (AG007).
- `backend.protocol` is `https` (default) or `http`.

## Rules

| Rule | Severity | What it flags |
| ---- | -------- | ------------- |
| AG001 | high | route on a public gateway with no authentication |
| AG002 | high | CORS allows credentials from any origin (`*`) |
| AG003 | high | backend protocol is plain http (unencrypted gateway-to-backend hop) |
| AG004 | medium | no rate limit on a route |
| AG005 | medium | logging disabled on a deployment |
| AG006 | medium | CORS allows any origin (`*`) without credentials |
| AG007 | low | request validation off |
| AG008 | low | route allows more than 5 HTTP methods |
| AG009 | low | wildcard route path (broad match) |
| AG010 | medium | no daily usage quota on a route |
| AG011 | medium | JWT/OAUTH2 route audience missing from `config.expected_audiences`, or no audience declared |

## Limits and honesty

- Offline only: no API calls, no live gateway checks. Whether a route is actually reachable or a policy actually enforced cannot be verified from a file.
- Rules check the configuration as written. AG001 cannot tell whether an upstream proxy adds authentication the file does not show.
- AG011 compares strings only; it does not validate tokens, issuers or keys - that needs live identity-provider access, which this tool never uses.
- CORS findings reflect the policy as configured, not what browsers will do with it.
- The schema is a simplification: real OCI API Gateway exports carry more fields (mutual TLS, header transforms, stock response routes) that this model ignores.
- The importer validates shape, not meaning: it passes mapped fields through and the audit rules judge them. Importer line numbers are best-effort (a text search for the route's path or backend url), not a real JSON parse position.

## Development

```
PYTHONPATH=src python3 -m unittest discover -s tests
```

Tests cover each rule and boundary (rate limit at the smallest allowed value vs absent, quota at 1 vs absent, method set at exactly 5 vs 6, wildcard origin among specific origins, private vs public gateways for AG001, AG002 taking precedence over AG006), validation errors, CLI exit codes and the importer (OCI-style conversion, envelope variants, quota and logging mapping, malformed rows with line numbers). `examples/good.json` must produce zero findings and `examples/risky.json` must trigger all 11 rules. CI runs the suite on Python 3.10, 3.11 and 3.12 plus CLI smoke checks on both examples.
