"""Pruebas de integración contra ambos servicios y una SQLite temporal."""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

from lab.local import healthy, wait_for_health


ROOT = Path(__file__).resolve().parents[1]


def request(port, method, route, body=None, headers=None, source_ip=None, host="127.0.0.1"):
    connection = HTTPConnection(
        host, port, timeout=8,
        source_address=(source_ip, 0) if source_ip else None,
    )
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
        directory = tempfile.TemporaryDirectory(dir=ROOT, ignore_cleanup_errors=True)
        cls.addClassCleanup(directory.cleanup)
        cls.ingest = {"Authorization": f"Bearer {secrets.token_urlsafe(24)}"}
        cls.admin = {"Authorization": f"Bearer {secrets.token_urlsafe(24)}"}
        cls.password = secrets.token_urlsafe(24)
        cls.source_addresses = [
            value for value in socket.gethostbyname_ex(socket.gethostname())[2]
            if not ip_address(value).is_loopback and ip_address(value).is_private
        ]
        cls.environment = {
            **os.environ,
            "DATABASE_URL": f"sqlite:///{(Path(directory.name) / 'test.db').as_posix()}",
            "INGEST_TOKEN": cls.ingest["Authorization"].split()[1],
            "ADMIN_TOKEN": cls.admin["Authorization"].split()[1],
            "BACKEND_URL": "http://127.0.0.1:18060",
            "LAB_USERNAME": "admin",
            "LAB_PASSWORD": cls.password,
            "LAB_CIDRS": ",".join(["10.231.37.0/28", *[f"{ip}/32" for ip in cls.source_addresses]]),
            "ALLOWLIST": "10.231.37.1",
            "WINDOW_SECONDS": "60",
            "MEDIUM_THRESHOLD": "3",
            "HIGH_THRESHOLD": "5",
            "AI_ENABLED": "false",
            "AUTO_CONTAINMENT": "true",
            "BLOCK_SECONDS": "4",
        }
        cls.backend = cls.start("backend.main:app", 18060)
        cls.protected = cls.start("protected_app.main:app", 18061)

    @classmethod
    def start(cls, module, port, environment=None, host="127.0.0.1"):
        if healthy(port):
            raise RuntimeError(f"Puerto de integración ocupado: {port}")
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", module, "--host", host,
             "--port", str(port), "--no-proxy-headers", "--log-level", "warning"],
            cwd=ROOT,
            env=environment or cls.environment,
        )
        cls.addClassCleanup(cls.stop, process)
        if host == "127.0.0.1":
            wait_for_health(process, port)
        else:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    if request(port, "GET", "/health", host=host)[0] == 200:
                        return process
                except OSError:
                    time.sleep(.15)
            raise RuntimeError("El servicio de prueba no inició en la IP local")
        return process

    @staticmethod
    def stop(process):
        if process.poll() is not None:
            return
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True)
        else:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

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
        self.assertEqual(metrics["verified_blocks"], baseline["verified_blocks"])
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
            for source_ip, expected in [("10.231.37.1", "review"), ("10.231.37.4", "pending_verification")]:
                receipt = None
                for delay in [120, 4, 3, 2, 1, 0]:
                    body = {**base, "source_ip": source_ip, "timestamp": (now - timedelta(seconds=delay)).isoformat()}
                    status, receipt = request(18060, "POST", "/api/events", body, self.ingest)
                    self.assertEqual(status, 201)
                self.assertEqual(receipt["severity"], "high")
                _, incident = request(18060, "GET", f"/api/incidents/{receipt['incident_id']}", headers=self.admin)
                self.assertEqual((incident["event_count"], incident["status"]), (5, expected))
    def test_containment_blocks_and_releases(self):
        now = datetime.now(UTC)
        source_ip = "10.231.37.7"
        for delay in [4, 3, 2, 1, 0]:
            body = {
                "event_type": "failed_login", "source_ip": source_ip, "target": "servidor-web",
                "timestamp": (now - timedelta(seconds=delay)).isoformat(),
                "metadata": {"username": "admin", "success": False},
            }
            status, receipt = request(18060, "POST", "/api/events", body, self.ingest)
            self.assertEqual(status, 201)

        check = f"/api/blocks/check?source_ip={source_ip}&target=servidor-web"
        self.assertTrue(request(18060, "GET", check, headers=self.ingest)[1]["blocked"])
        _, incident = request(18060, "GET", f"/api/incidents/{receipt['incident_id']}", headers=self.admin)
        self.assertEqual(incident["status"], "pending_verification")

        _, blocks = request(18060, "GET", "/api/blocks?active_only=true", headers=self.admin)
        block = next(item for item in blocks if item["source_ip"] == source_ip)
        status, released = request(18060, "POST", f"/api/blocks/{block['id']}/release", headers=self.admin)
        self.assertEqual((status, released["status"]), (200, "released"))
        self.assertFalse(request(18060, "GET", check, headers=self.ingest)[1]["blocked"])

        _, audit = request(18060, "GET", "/api/audit", headers=self.admin)
        actions = [entry["action"] for entry in audit if entry["source_ip"] == source_ip]
        self.assertIn("block_created", actions)
        self.assertIn("block_released", actions)

    def test_real_socket_containment_and_recovery(self):
        if not self.source_addresses:
            self.skipTest("La máquina requiere una IP local privada conectable para probar un origen real")
        source_ip = self.source_addresses[-1]
        self.start("protected_app.main:app", 18063, host=source_ip)

        def protected(method, path, body=None):
            return request(18063, method, path, body, source_ip=source_ip, host=source_ip)

        self.assertEqual(protected("GET", "/access"),
                         (200, {"status": "accessible", "source_ip": source_ip, "target": "servidor-web"}))

        def fail_login():
            return protected("POST", "/login", {"username": "admin", "password": "invalid-test"})

        for _ in range(5):
            self.assertEqual(fail_login()[0], 401)
        check = f"/api/blocks/check?source_ip={source_ip}&target=servidor-web"
        block = request(18060, "GET", check, headers=self.ingest)[1]
        self.assertTrue(block["blocked"])
        _, incidents = request(18060, "GET", "/api/incidents", headers=self.admin)
        incident = next(item for item in incidents["items"] if item["source_ip"] == source_ip)
        self.assertEqual(incident["status"], "pending_verification")
        valid_login = {"username": "admin", "password": self.password}
        denied = protected("POST", "/login", valid_login)
        self.assertEqual((denied[0], denied[1]["source_ip"]), (403, source_ip))
        _, verified = request(18060, "GET", f"/api/incidents/{incident['id']}", headers=self.admin)
        self.assertEqual(verified["status"], "contained")
        metrics = request(18060, "GET", "/api/metrics", headers=self.admin)[1]
        self.assertGreaterEqual(metrics["verified_blocks"], 1)
        self.assertEqual(protected("GET", "/access")[0], 403)

        released = request(18060, "POST", f"/api/blocks/{block['block_id']}/release", headers=self.admin)
        self.assertEqual(released[0], 200)
        self.assertEqual(protected("GET", "/access")[0], 200)
        _, restored = request(18060, "GET", f"/api/incidents/{incident['id']}", headers=self.admin)
        self.assertEqual(restored["status"], "restored")

        self.assertEqual(fail_login()[0], 401)
        self.assertEqual(protected("GET", "/access")[0], 403)
        time.sleep(4.2)
        self.assertEqual(protected("GET", "/access")[0], 200)
        self.assertEqual(protected("POST", "/login", valid_login)[0], 200)
        _, audit = request(18060, "GET", "/api/audit?limit=200", headers=self.admin)
        operations = [item["action"] for item in audit if item["source_ip"] == source_ip]
        self.assertIn("block_expired", operations)
        self.assertIn("block_verified", operations)
        self.assertIn("access_restored", operations)

    def test_service_fails_closed_without_backend(self):
        unavailable = {**self.environment, "BACKEND_URL": "http://127.0.0.1:1"}
        process = self.start("protected_app.main:app", 18062, unavailable)
        try:
            self.assertEqual(request(18062, "GET", "/access")[0], 503)
            self.assertEqual(request(18062, "POST", "/login", {"username": "admin", "password": self.password})[0], 503)
            self.assertEqual(request(18062, "GET", "/health")[0], 200)
            self.assertEqual(request(18062, "GET", "/")[0], 200)
        finally:
            self.stop(process)

    def test_dashboard_assets(self):
        for asset in ("", "dashboard.css", "dashboard.js"):
            status, content = request(18060, "GET", f"/dashboard/{asset}")
            self.assertEqual(status, 200)
            self.assertTrue(content)
        for asset in ("", "lab.css", "lab.js"):
            self.assertEqual(request(18061, "GET", f"/{asset}")[0], 200)


if __name__ == "__main__":
    unittest.main()
