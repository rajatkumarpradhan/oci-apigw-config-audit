import json
import os
import tempfile
import unittest

from apigw_audit import analysis, model
from apigw_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def route(**kw):
    d = {"path": "/ok", "methods": ["GET"], "auth": "JWT",
         "cors": {"allowed_origins": ["https://app.example.com"], "allow_credentials": False},
         "rate_limit_rps": 10, "quota_per_day": 1000,
         "request_validation": True, "backend": {"protocol": "https"}}
    d.update(kw)
    return d


def gw(routes, endpoint="PUBLIC", logging=True, prefix="/api"):
    return {"gateway": "test-gw", "endpoint_type": endpoint,
            "deployments": [{"path_prefix": prefix, "logging": logging, "routes": routes}]}


def run(d):
    return analysis.analyze(model.load(d))


def rules(d):
    return {f.rule for f in run(d)}


class ExampleTests(unittest.TestCase):
    def test_good_is_clean(self):
        self.assertEqual(run(json.load(open(os.path.join(EX, "good.json"), encoding="utf-8"))), [])

    def test_risky_triggers_every_rule(self):
        d = json.load(open(os.path.join(EX, "risky.json"), encoding="utf-8"))
        self.assertEqual(rules(d), {f"AG{n:03d}" for n in range(1, 11)})

    def test_sorted_by_severity(self):
        d = json.load(open(os.path.join(EX, "risky.json"), encoding="utf-8"))
        s = [analysis.SEV[f.severity] for f in run(d)]
        self.assertEqual(s, sorted(s))


class AuthRuleTests(unittest.TestCase):
    def test_public_route_without_auth(self):
        self.assertIn("AG001", rules(gw([route(auth="NONE")])))
        self.assertNotIn("AG001", rules(gw([route(auth="NONE")], endpoint="PRIVATE")))
        for a in ("JWT", "OAUTH2", "FUNCTIONS"):
            self.assertNotIn("AG001", rules(gw([route(auth=a)])))

    def test_private_gateway_never_flags_ag001(self):
        self.assertNotIn("AG001", rules(gw([route(auth="NONE")], endpoint="PRIVATE")))


class CorsRuleTests(unittest.TestCase):
    def test_wildcard_with_credentials_is_high(self):
        f = [x for x in run(gw([route(cors={"allowed_origins": ["*"], "allow_credentials": True})]))]
        self.assertIn("AG002", {x.rule for x in f})
        self.assertNotIn("AG006", {x.rule for x in f})
        self.assertEqual([x for x in f if x.rule == "AG002"][0].severity, "high")

    def test_wildcard_without_credentials_is_medium(self):
        f = [x for x in run(gw([route(cors={"allowed_origins": ["*"]})]))]
        self.assertIn("AG006", {x.rule for x in f})
        self.assertNotIn("AG002", {x.rule for x in f})

    def test_specific_origins_clean(self):
        self.assertNotIn("AG002", rules(gw([route()])))
        self.assertNotIn("AG006", rules(gw([route()])))

    def test_wildcard_among_specific_origins_still_flags(self):
        self.assertIn("AG006", rules(gw([route(cors={"allowed_origins": ["https://a.example.com", "*"]})])))


class BackendRuleTests(unittest.TestCase):
    def test_http_backend_flagged(self):
        self.assertIn("AG003", rules(gw([route(backend={"protocol": "http"})])))
        self.assertNotIn("AG003", rules(gw([route(backend={"protocol": "https"})])))
        self.assertNotIn("AG003", rules(gw([route(backend={})])))


class LimitRuleTests(unittest.TestCase):
    def test_rate_limit_boundary(self):
        self.assertIn("AG004", rules(gw([route(rate_limit_rps=None)])))
        self.assertNotIn("AG004", rules(gw([route(rate_limit_rps=0.001)])))
        self.assertNotIn("AG004", rules(gw([route(rate_limit_rps=1000)])))

    def test_quota_boundary(self):
        self.assertIn("AG010", rules(gw([route(quota_per_day=None)])))
        self.assertNotIn("AG010", rules(gw([route(quota_per_day=1)])))

    def test_logging_flag(self):
        self.assertIn("AG005", rules(gw([route()], logging=False)))
        self.assertNotIn("AG005", rules(gw([route()], logging=True)))

    def test_validation_flag(self):
        self.assertIn("AG007", rules(gw([route(request_validation=False)])))
        self.assertNotIn("AG007", rules(gw([route(request_validation=True)])))


class ShapeRuleTests(unittest.TestCase):
    def test_method_count_boundary(self):
        five = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        six = five + ["HEAD"]
        self.assertNotIn("AG008", rules(gw([route(methods=five)])))
        self.assertIn("AG008", rules(gw([route(methods=six)])))

    def test_wildcard_path(self):
        self.assertIn("AG009", rules(gw([route(path="/admin/*")])))
        self.assertIn("AG009", rules(gw([route(path="/a/*/b")])))
        self.assertNotIn("AG009", rules(gw([route(path="/admin")])))
        self.assertNotIn("AG009", rules(gw([route(path="/")])))  # prefix-root, not a wildcard


class ValidationTests(unittest.TestCase):
    def bad(self, mutate):
        d = gw([route()])
        mutate(d)
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_errors(self):
        cases = [
            lambda d: d.update(gateway=""),
            lambda d: d.update(endpoint_type="INTERNAL"),
            lambda d: d.update(deployments="x"),
            lambda d: d["deployments"].append("x"),
            lambda d: d["deployments"][0].update(path_prefix="api"),
            lambda d: d["deployments"][0].update(logging="yes"),
            lambda d: d["deployments"][0].update(routes="x"),
            lambda d: d["deployments"][0]["routes"].append("x"),
            lambda d: d["deployments"][0]["routes"][0].update(path="ok"),
            lambda d: d["deployments"][0]["routes"][0].update(methods=[]),
            lambda d: d["deployments"][0]["routes"][0].update(methods=["YEET"]),
            lambda d: d["deployments"][0]["routes"][0].update(auth="BASIC"),
            lambda d: d["deployments"][0]["routes"][0].update(cors="x"),
            lambda d: d["deployments"][0]["routes"][0].update(cors={"allowed_origins": "*"}),
            lambda d: d["deployments"][0]["routes"][0].update(cors={"allow_credentials": "true"}),
            lambda d: d["deployments"][0]["routes"][0].update(rate_limit_rps=0),
            lambda d: d["deployments"][0]["routes"][0].update(rate_limit_rps=True),
            lambda d: d["deployments"][0]["routes"][0].update(quota_per_day=0),
            lambda d: d["deployments"][0]["routes"][0].update(quota_per_day=2.5),
            lambda d: d["deployments"][0]["routes"][0].update(request_validation="no"),
            lambda d: d["deployments"][0]["routes"][0].update(backend="x"),
            lambda d: d["deployments"][0]["routes"][0].update(backend={"protocol": "ftp"}),
        ]
        for m in cases:
            with self.subTest(m=m):
                self.bad(m)


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(main([os.path.join(EX, "good.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "good.json"), "--fail-on", "low"]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "medium"]), 2)

    def test_fail_on_none_means_zero(self):
        self.assertEqual(main([os.path.join(EX, "risky.json")]), 0)

    def test_report_and_errors(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            main([os.path.join(EX, "risky.json"), "--output", out])
            rep = json.load(open(out, encoding="utf-8"))
            self.assertIn("No API calls are made", rep["disclaimer"])
            self.assertEqual(rep["gateway"], "legacy-gw")
            self.assertEqual(len(rep["findings"]), 10)
            bad = os.path.join(t, "b.json")
            open(bad, "w").write("{oops")
            self.assertEqual(main([bad]), 1)
            self.assertEqual(main([os.path.join(t, "none.json")]), 1)


if __name__ == "__main__":
    unittest.main()
