"""Pruebas de integración contra ambos servicios y una SQLite temporal."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from pathlib import Path
from uuid import uuid4

from lab.local import healthy, wait_for_health


ROOT = Path(__file__).resolve().parents[1]


def request(port, method, route, body=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            method, route,
            json.dumps(body) if body is not None else None,
            {"Content-Type": "application/json", **(headers or {})},
        )
        with connection.getresponse() as response:
            content = response.read()
            if response.headers.get("Content-Type", "").startswith("application/json"):
                content = json.loads(content)
            return response.status, content
    finally:
        connection.close()


class LabIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(dir=ROOT)
        cls.addClassCleanup(directory.cleanup)
        cls.ingest = {"Authorization": f"Bearer {secrets.token_urlsafe(24)}"}
        cls.admin = {"Authorization": f"Bearer {secrets.token_urlsafe(24)}"}
        cls.password = secrets.token_urlsafe(24)
        cls.environment = {
            **os.environ,
            "DATABASE_URL": f"sqlite:///{(Path(directory.name) / 'test.db').as_posix()}",
            "INGEST_TOKEN": cls.ingest["Authorization"].split()[1],
            "ADMIN_TOKEN": cls.admin["Authorization"].split()[1],
            "BACKEND_URL": "http://127.0.0.1:18060",
            "LAB_USERNAME": "admin",
            "LAB_PASSWORD": cls.password,
            "LAB_CIDRS": "10.231.37.0/28",
            "ALLOWLIST": "10.231.37.1",
            "WINDOW_SECONDS": "60",
            "MEDIUM_THRESHOLD": "3",
            "HIGH_THRESHOLD": "5",
        }
        cls.backend = cls.start("backend.main:app", 18060)
        cls.protected = cls.start("protected_app.main:app", 18061)

    @classmethod
    def start(cls, module, port):
        if healthy(port):
            raise RuntimeError(f"Puerto de integración ocupado: {port}")
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1",
             "--port", str(port), "--no-proxy-headers", "--log-level", "warning"],
            cwd=ROOT,
            env=cls.environment,
        )
        cls.addClassCleanup(cls.stop, process)
        wait_for_health(process, port)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)

    def test_failures_create_and_upgrade_one_incident(self):
        _, baseline = request(18060, "GET", "/api/metrics", headers=self.admin)
        for event_index in range(6):
            login = {"username": "admin", "password": "invalid-test"}
            self.assertEqual(
                request(18061, "POST", "/login", login, {"X-Forwarded-For": "10.231.37.4"})[0],
                401,
            )
            if event_index == 2:
                _, page = request(18060, "GET", "/api/incidents?severity=medium", headers=self.admin)
                self.assertEqual(page["total"], 1)
                incident_id = page["items"][0]["id"]

        status, incident = request(18060, "GET", f"/api/incidents/{incident_id}", headers=self.admin)
        self.assertEqual(status, 200)
        self.assertEqual((incident["severity"], incident["status"], incident["source_ip"]),
                         ("high", "review", "127.0.0.1"))
        self.assertEqual((incident["event_count"], incident["attempts"], len(incident["events"])), (6, 6, 6))
        self.assertTrue(all(event["metadata"] == {"username": "admin", "success": False}
                            for event in incident["events"]))
        _, metrics = request(18060, "GET", "/api/metrics", headers=self.admin)
        self.assertEqual(metrics["events"], baseline["events"] + 6)
        self.assertEqual(metrics["incidents"], baseline["incidents"] + 1)
        self.assertEqual(metrics["verified_blocks"], 0)
        self.assertEqual(request(18061, "POST", "/login", {"username": "admin", "password": self.password})[0], 200)
        self.assertEqual(request(18060, "GET", "/api/metrics", headers=self.admin)[1], metrics)

    def test_idempotency_and_role_separation(self):
        payload = {
            "event_type": "failed_login", "source_ip": "10.231.37.5", "target": "servidor-web",
            "timestamp": datetime.now(UTC).isoformat(), "metadata": {"username": "admin", "success": False},
        }
        self.assertEqual(request(18060, "POST", "/api/events", payload, self.admin)[0], 401)
        self.assertEqual(request(18060, "GET", "/api/metrics", headers=self.ingest)[0], 401)
        self.assertEqual(request(18060, "GET", "/api/incidents")[0], 401)
        headers = {**self.ingest, "Idempotency-Key": str(uuid4())}
        first = request(18060, "POST", "/api/events", payload, headers)
        self.assertEqual(first[0], 201)
        self.assertEqual(request(18060, "POST", "/api/events", payload, headers), first)
        payload["source_ip"] = "10.231.37.6"
        self.assertEqual(request(18060, "POST", "/api/events", payload, headers)[0], 409)
        payload["timestamp"] = "2026-11-14T15:30:00"
        self.assertEqual(request(18060, "POST", "/api/events", payload, self.ingest)[0], 422)

    def test_window_and_allowlist(self):
        now = datetime.now(UTC)
        base = {"event_type": "failed_login", "target": "servidor-web",
                "metadata": {"username": "admin", "success": False}}
        for source_ip, expected in [("10.231.37.1", "review"), ("10.231.37.4", "pending_containment")]:
            receipt = None
            for delay in [120, 4, 3, 2, 1, 0]:
                body = {**base, "source_ip": source_ip, "timestamp": (now - timedelta(seconds=delay)).isoformat()}
                status, receipt = request(18060, "POST", "/api/events", body, self.ingest)
                self.assertEqual(status, 201)
            self.assertEqual(receipt["severity"], "high")
            _, incident = request(18060, "GET", f"/api/incidents/{receipt['incident_id']}", headers=self.admin)
            self.assertEqual((incident["event_count"], incident["status"]), (5, expected))

    def test_dashboard_assets(self):
        for asset in ("", "dashboard.css", "dashboard.js"):
            status, content = request(18060, "GET", f"/dashboard/{asset}")
            self.assertEqual(status, 200)
            self.assertTrue(content)


if __name__ == "__main__":
    unittest.main()
