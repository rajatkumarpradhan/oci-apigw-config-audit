import json
import os
import tempfile
import unittest

from apigw_audit import analysis, importer, model
from apigw_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def export(routes, envelope=True, deployments_extra=None):
    dep = {"path-prefix": "/api",
           "specification": {"logging-policies": {"access-log": {"is-enabled": True}},
                             "routes": routes}}
    if deployments_extra:
        dep["specification"].update(deployments_extra)
    data = {"display-name": "test-gw", "endpoint-type": "PUBLIC", "deployments": [dep]}
    return json.dumps({"data": data} if envelope else data)


def route(path="/ok", url="https://b.internal/ok", **policies):
    r = {"path": path, "methods": ["GET"], "backend": {"type": "HTTP_BACKEND", "url": url}}
    if policies:
        r["request-policies"] = policies
    return r


class ConvertTests(unittest.TestCase):
    def test_fixture_round_trips_clean(self):
        gw = importer.load_export(os.path.join(EX, "export.json"))
        self.assertEqual(analysis.analyze(model.load(gw)), [])

    def test_unwrapped_shape(self):
        gw = importer.convert(export([route()], envelope=False))
        self.assertEqual(gw["gateway"], "test-gw")
        self.assertEqual(len(gw["deployments"][0]["routes"]), 1)

    def test_bad_top_level(self):
        with self.assertRaises(importer.ImportError):
            importer.convert("[1, 2]")
        with self.assertRaises(importer.ImportError):
            importer.convert('{"data": {"no-name": true}}')

    def test_route_mapping(self):
        gw = importer.convert(export([route("/charge", "http://b.internal/x",
                                            authentication={"type": "JWT_AUTHENTICATION"},
                                            cors={"allowed-origins": ["*"], "is-allow-credentials-enabled": True},
                                            **{"rate-limiting": {"rate-in-requests-per-second": 5},
                                               "body-validation": {"required": True}})]))
        r = gw["deployments"][0]["routes"][0]
        self.assertEqual((r["auth"], r["backend"]["protocol"], r["rate_limit_rps"]), ("JWT", "http", 5))
        self.assertEqual(r["cors"], {"allowed_origins": ["*"], "allow_credentials": True})
        self.assertTrue(r["request_validation"])

    def test_defaults(self):
        gw = importer.convert(export([route()]))
        r = gw["deployments"][0]["routes"][0]
        self.assertEqual(r["auth"], "NONE")
        self.assertNotIn("rate_limit_rps", r)
        self.assertNotIn("quota_per_day", r)
        self.assertFalse(r["request_validation"])

    def test_daily_quota_maps_from_usage_plans(self):
        gw = importer.convert(export([route()], deployments_extra={
            "usage-plans": [{"quota": {"number-of-requests": 500, "reset-period": "MONTH"}},
                            {"quota": {"number-of-requests": 100, "reset-period": "DAY"}}]}))
        self.assertEqual(gw["deployments"][0]["routes"][0]["quota_per_day"], 100)

    def test_non_daily_quota_left_unset(self):
        gw = importer.convert(export([route()], deployments_extra={
            "usage-plans": [{"quota": {"number-of-requests": 500, "reset-period": "MONTH"}}]}))
        self.assertNotIn("quota_per_day", gw["deployments"][0]["routes"][0])

    def test_logging_from_either_policy(self):
        gw = importer.convert(export([route()]))
        self.assertTrue(gw["deployments"][0]["logging"])
        gw = importer.convert(export([route()], deployments_extra={
            "logging-policies": {"access-log": {"is-enabled": False}, "execution-log": {"is-enabled": False}}}))
        self.assertFalse(gw["deployments"][0]["logging"])


TEXT = """{
 "data": {
  "display-name": "bad-gw",
  "endpoint-type": "PUBLIC",
  "deployments": [
   {"path-prefix": "/api", "specification": {"routes": [
    {"path": "/fine", "methods": ["GET"], "backend": {"url": "https://b.internal/fine"}},
    {"methods": ["GET"], "backend": {"url": "https://b.internal/no-path"}},
    {"path": "/bad-backend", "methods": ["GET"], "backend": {"url": "ftp://b.internal/x"}},
    "oops",
    {"path": "/also-fine", "methods": ["GET"], "backend": {"url": "https://b.internal/ok"}}
   ]}}
  ]
 }
}"""


class ErrorTests(unittest.TestCase):
    def test_all_bad_rows_reported_with_lines(self):
        with self.assertRaises(importer.ImportError) as ctx:
            importer.convert(TEXT)
        msg = str(ctx.exception)
        self.assertNotIn("routes[0]", msg)
        self.assertIn("routes[1] (line 8)", msg)
        self.assertIn("routes[2] (line 9)", msg)
        self.assertIn("routes[3] (line 1)", msg)
        self.assertNotIn("routes[4]", msg)
        self.assertIn("path missing", msg)
        self.assertIn("scheme", msg)
        self.assertIn("not an object", msg)


class CliTests(unittest.TestCase):
    def test_import_then_audit(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "gw.json")
            self.assertEqual(main(["import", os.path.join(EX, "export.json"), "-o", out]), 0)
            self.assertEqual(main([out, "--fail-on", "low"]), 0)

    def test_import_stdout(self):
        self.assertEqual(main(["import", os.path.join(EX, "export.json")]), 0)

    def test_import_errors(self):
        with tempfile.TemporaryDirectory() as t:
            bad = os.path.join(t, "b.json")
            open(bad, "w").write(TEXT)
            self.assertEqual(main(["import", bad]), 1)
            open(bad, "w").write("{oops")
            self.assertEqual(main(["import", bad]), 1)
            self.assertEqual(main(["import", os.path.join(t, "none.json")]), 1)

    def test_plain_run_unchanged(self):
        self.assertEqual(main([os.path.join(EX, "good.json"), "--fail-on", "low"]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)


if __name__ == "__main__":
    unittest.main()
