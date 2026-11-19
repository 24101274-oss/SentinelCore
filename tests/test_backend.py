"""Regresiones de políticas, evidencia y migración sin conexiones externas."""

import sqlite3
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.analyst import AnalystError, Decision, ask_model, drain_pending, parse_decision, run_analyst
from backend.api.routes import (
    ObservationPayload,
    check_block,
    export_incident,
    get_metrics,
    ingest_event,
    observe_access,
    release_block,
    respond_incident,
)
from backend.api.schemas import EventPayload
from backend.config import Settings
from backend.containment import utc_now
from backend.database import open_database
from backend.models import AuditEntry, Block, Incident
from backend.main import create_app


class BackendPolicyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.settings = Settings(
            "ingest-test", "admin-test",
            database_url=f"sqlite:///{Path(self.directory.name) / 'test.db'}",
            lab_networks=(ip_network("10.231.37.0/24"),),
            ai_enabled=True, ai_api_key="test-key",
        )
        self.engine = open_database(self.settings.database_url)
        self.addCleanup(self.engine.dispose)
        self.request = SimpleNamespace(app=SimpleNamespace(
            state=SimpleNamespace(settings=self.settings, engine=self.engine)
        ))

    def ingest(self, source_ip="10.231.37.4", username="admin"):
        payload = EventPayload(
            event_type="failed_login", source_ip=source_ip, target="servidor-web",
            timestamp=utc_now().isoformat() + "Z",
            metadata={"username": username, "success": False},
        )
        with Session(self.engine) as session:
            return ingest_event(payload, self.request, session, BackgroundTasks(), None)

    def trigger(self, source_ip="10.231.37.4", usernames=None):
        for username in usernames or ["admin"] * 5:
            receipt = self.ingest(source_ip, username)
        return str(receipt.incident_id)

    def incident_status(self, incident_id):
        with Session(self.engine) as session:
            return session.get(Incident, incident_id).status

    def test_model_block_requires_protected_service_evidence(self):
        incident_id = self.trigger()
        with patch("backend.analyst.ask_model", return_value=Decision("block", .95, "Umbral alto")):
            run_analyst(self.engine, incident_id, self.settings)
        self.assertEqual(self.incident_status(incident_id), "pending_verification")

        with Session(self.engine) as session:
            self.assertEqual(get_metrics(session).verified_blocks, 0)
            block = check_block("10.231.37.4", "servidor-web", session)
        observation = ObservationPayload(
            source_ip="10.231.37.4", target="servidor-web",
            http_status=403, request_id=uuid4(), block_id=block.block_id,
        )
        for _ in range(2):
            with Session(self.engine) as session:
                self.assertEqual(observe_access(observation, session)["incident_status"], "contained")
        with Session(self.engine) as session:
            self.assertEqual(get_metrics(session).verified_blocks, 1)
            count = session.scalar(select(func.count()).select_from(AuditEntry).where(
                AuditEntry.action == "block_verified"
            ))
            self.assertEqual(count, 1)
            session.rollback()
            release_block(block.block_id, session)
        self.assertEqual(self.incident_status(incident_id), "restoration_pending")
        with Session(self.engine) as session:
            allowed = ObservationPayload(
                source_ip="10.231.37.4", target="servidor-web",
                http_status=200, request_id=uuid4(),
            )
            self.assertEqual(observe_access(allowed, session)["incident_status"], "restored")
            self.assertEqual(get_metrics(session).restored_access, 1)

    def test_timeout_falls_back_to_policy_checked_rule(self):
        incident_id = self.trigger()
        with patch("backend.analyst.ask_model", side_effect=AnalystError("timeout")):
            run_analyst(self.engine, incident_id, self.settings)
        self.assertEqual(self.incident_status(incident_id), "pending_verification")
        with Session(self.engine) as session:
            self.assertIsNotNone(session.scalar(select(AuditEntry).where(
                AuditEntry.action == "ai_fallback"
            )))

    def test_unexpected_provider_error_falls_back_without_exposing_exception(self):
        incident_id = self.trigger()
        with patch("backend.analyst.ask_model", side_effect=RuntimeError("secret-provider-key")):
            with self.assertLogs("uvicorn.error", level="WARNING") as logs:
                run_analyst(self.engine, incident_id, self.settings)
        self.assertNotIn("secret-provider-key", " ".join(logs.output))
        self.assertEqual(self.incident_status(incident_id), "pending_verification")
        with Session(self.engine) as session:
            self.assertIsNone(session.get(Incident, incident_id).ai_started_at)
            self.assertIsNotNone(session.scalar(select(AuditEntry).where(
                AuditEntry.action == "ai_fallback"
            )))

    def test_recovery_reclaims_stale_work_and_preserves_current_claim(self):
        stale_id = self.trigger()
        current_id = self.trigger("10.231.37.5")
        with Session(self.engine) as session:
            session.get(Incident, stale_id).ai_started_at = utc_now() - timedelta(seconds=60)
            session.get(Incident, current_id).ai_started_at = utc_now()
            session.commit()
        with patch("backend.analyst.ask_model", return_value=Decision("block", .95, "Recuperado")) as model:
            drain_pending(self.engine, self.settings)
            drain_pending(self.engine, self.settings)
            self.assertEqual(model.call_count, 1)
        self.assertEqual(self.incident_status(stale_id), "pending_verification")
        self.assertEqual(self.incident_status(current_id), "pending_containment")

    def test_recovery_uses_fixed_rules_when_ai_is_disabled(self):
        incident_id = self.trigger()
        with patch("backend.analyst.ask_model") as model:
            drain_pending(self.engine, replace(self.settings, ai_enabled=False))
            model.assert_not_called()
        self.assertEqual(self.incident_status(incident_id), "pending_verification")

    def test_downloadable_export_contains_only_linked_evidence_and_public_settings(self):
        self.request.app.state.settings = replace(self.settings, ai_enabled=False)
        incident_id = self.trigger()
        self.trigger("10.231.37.5")
        with Session(self.engine) as session:
            block = check_block("10.231.37.4", "servidor-web", session)
            session.rollback()
            observe_access(ObservationPayload(
                source_ip="10.231.37.4", target="servidor-web",
                http_status=403, request_id=uuid4(), block_id=block.block_id,
            ), session)
            release_block(block.block_id, session)
            observe_access(ObservationPayload(
                source_ip="10.231.37.4", target="servidor-web",
                http_status=200, request_id=uuid4(),
            ), session)
            response = export_incident(UUID(incident_id), self.request, session)
        exported = json.loads(response.body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["Content-Disposition"],
            f'attachment; filename="sentinelcore-{incident_id}-evidence.json"',
        )
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(exported["format_version"], "sentinelcore-evidence/1.0")
        self.assertEqual(exported["parameters_basis"], "current_runtime")
        self.assertEqual(datetime.fromisoformat(exported["generated_at"]).utcoffset(), timedelta(0))
        self.assertEqual(exported["incident"]["id"], incident_id)
        self.assertEqual(len(exported["incident"]["events"]), 5)
        self.assertEqual(exported["incident"]["status"], "restored")
        self.assertEqual(len(exported["blocks"]), 1)
        self.assertTrue(exported["blocks"][0]["verified_at"])
        self.assertTrue(exported["blocks"][0]["restored_at"])
        self.assertEqual(
            {entry["action"] for entry in exported["audit"]},
            {"block_created", "block_verified", "block_released", "access_restored"},
        )
        self.assertTrue(all(entry["incident_id"] == incident_id for entry in exported["audit"]))
        self.assertEqual(exported["parameters"]["high_threshold"], self.settings.high_threshold)
        rendered = response.body.decode()
        for secret in (self.settings.ingest_token, self.settings.admin_token, self.settings.ai_api_key):
            self.assertNotIn(secret, rendered)
        for key in ("ingest_token", "admin_token", "ai_api_key", "AI_API_KEY"):
            self.assertNotIn(key, rendered)
        self.assertNotIn("10.231.37.5", rendered)

    def test_export_unknown_incident_and_openapi_contract(self):
        with Session(self.engine) as session:
            with self.assertRaises(HTTPException) as error:
                export_incident(uuid4(), self.request, session)
            self.assertEqual(error.exception.status_code, 404)
        operation = create_app(self.settings).openapi()["paths"]["/api/incidents/{incident_id}/export"]["get"]
        self.assertEqual(operation["security"], [{"HTTPBearer": []}])
        self.assertIn("Content-Disposition", operation["responses"]["200"]["headers"])

    def test_outbound_model_request_contains_only_aggregated_facts(self):
        incident_id = self.trigger(usernames=["cuenta-canaria"] * 5)
        with patch("backend.analyst.http.client.HTTPSConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = ModelResponseTest.envelope({
                "action": "block", "confidence": .95, "explanation": "Patrón agregado",
            })
            run_analyst(self.engine, incident_id, self.settings)
        method, path, body, _headers = connection.request.call_args.args
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/openai/v1/chat/completions")
        sent = json.loads(body)
        facts = json.loads(next(message["content"] for message in sent["messages"] if message["role"] == "user"))
        self.assertEqual(set(facts), {
            "category", "failed_attempts", "event_count", "window_seconds",
            "seconds_between_first_and_last", "distinct_usernames",
        })
        self.assertEqual(facts["distinct_usernames"], 1)
        self.assertEqual(facts["failed_attempts"], 5)
        for sensitive in ("10.231.37.4", "cuenta-canaria", incident_id,
                          self.settings.ingest_token, self.settings.admin_token, self.settings.ai_api_key):
            self.assertNotIn(sensitive, body)

    def test_model_review_and_auto_off_never_create_blocks(self):
        incident_id = self.trigger()
        with patch("backend.analyst.ask_model", return_value=Decision("review", .99, "Revisar")):
            run_analyst(self.engine, incident_id, self.settings)
        self.assertEqual(self.incident_status(incident_id), "review")
        disabled = replace(self.settings, auto_containment=False)
        self.request.app.state.settings = disabled
        other_id = self.trigger("10.231.37.5")
        with patch("backend.analyst.ask_model") as model:
            run_analyst(self.engine, other_id, disabled)
            model.assert_not_called()
        with Session(self.engine) as session:
            self.assertEqual(get_metrics(session).active_blocks, 0)
            session.rollback()
            # El administrador conserva un control manual explícito.
            block = respond_incident(UUID(other_id), self.request, session)
            self.assertEqual(block.source_ip, "10.231.37.5")

    def test_policy_revalidated_after_model_request(self):
        incident_id = self.trigger()
        changed = replace(self.settings, allowlist=(ip_network("10.231.37.4"),))
        with patch("backend.analyst.ask_model", return_value=Decision("block", .99, "Bloquear")):
            run_analyst(self.engine, incident_id, changed)
        self.assertEqual(self.incident_status(incident_id), "review")
        with Session(self.engine) as session:
            self.assertEqual(get_metrics(session).active_blocks, 0)

    def test_limit_and_spraying_classification(self):
        limited = replace(self.settings, ai_enabled=False, max_active_blocks=1)
        self.request.app.state.settings = limited
        first = self.trigger(usernames=[f"cuenta-{index}" for index in range(5)])
        second = self.trigger("10.231.37.5")
        with Session(self.engine) as session:
            self.assertEqual(session.get(Incident, first).category, "possible_password_spraying")
            self.assertEqual(session.get(Incident, second).status, "review")
            self.assertEqual(get_metrics(session).active_blocks, 1)

    def test_expiry_rearms_and_rejects_mismatched_verification(self):
        self.request.app.state.settings = replace(self.settings, ai_enabled=False)
        incident_id = self.trigger()
        with Session(self.engine) as session:
            block = session.scalar(select(Block).where(Block.incident_id == incident_id))
            block_id = block.id
            block.expires_at = utc_now() - timedelta(seconds=1)
            session.commit()
            self.assertFalse(check_block("10.231.37.4", "servidor-web", session).blocked)
        self.ingest()
        self.assertEqual(self.incident_status(incident_id), "pending_verification")
        with Session(self.engine) as session:
            invalid = ObservationPayload(
                source_ip="10.231.37.5", target="servidor-web",
                http_status=403, request_id=uuid4(), block_id=block_id,
            )
            with self.assertRaises(HTTPException) as error:
                observe_access(invalid, session)
            self.assertEqual(error.exception.status_code, 409)


class LegacyMigrationTest(unittest.TestCase):
    def test_existing_evidence_and_unverified_blocks_survive_repeated_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.db"
            with sqlite3.connect(database) as connection:
                connection.executescript("""
                    CREATE TABLE incidents (
                        id VARCHAR(36) PRIMARY KEY, source_ip VARCHAR(45) NOT NULL,
                        target VARCHAR(100) NOT NULL, severity VARCHAR(6) NOT NULL,
                        status VARCHAR(20) NOT NULL, first_seen DATETIME NOT NULL,
                        last_seen DATETIME NOT NULL, event_count INTEGER NOT NULL,
                        attempts INTEGER NOT NULL, recommended_action VARCHAR(20) NOT NULL,
                        reason VARCHAR(300) NOT NULL
                    );
                    CREATE TABLE blocks (
                        id VARCHAR(36) PRIMARY KEY, incident_id VARCHAR(36) NOT NULL,
                        source_ip VARCHAR(45) NOT NULL, target VARCHAR(100) NOT NULL,
                        status VARCHAR(10) NOT NULL, created_at DATETIME NOT NULL,
                        expires_at DATETIME NOT NULL, released_at DATETIME
                    );
                    INSERT INTO incidents VALUES (
                        'legacy','10.231.37.4','servidor-web','high','contained',
                        '2026-11-19 00:00:00','2026-11-19 00:00:00',5,5,'temporary_block','evidencia previa'
                    );
                    INSERT INTO blocks VALUES (
                        'old-block','legacy','10.231.37.4','servidor-web','active',
                        '2026-11-19 00:00:00','2030-11-19 00:00:00',NULL
                    );
                """)
            connection.close()
            for _ in range(2):
                engine = open_database(f"sqlite:///{database}")
                try:
                    with Session(engine) as session:
                        incident = session.get(Incident, "legacy")
                        self.assertEqual(incident.reason, "evidencia previa")
                        self.assertEqual(incident.event_count, 5)
                        self.assertEqual(incident.category, "possible_brute_force")
                        self.assertEqual(incident.status, "pending_verification")
                        self.assertIsNone(session.get(Block, "old-block").verified_at)
                finally:
                    engine.dispose()


class ModelResponseTest(unittest.TestCase):
    @staticmethod
    def envelope(decision):
        return json.dumps({"choices": [{"message": {"content": json.dumps(decision)}}]}).encode()

    def test_invalid_decision_shapes_are_controlled_errors(self):
        valid = {"action": "block", "confidence": .95, "explanation": "Evidencia alta"}
        invalid = [
            {"action": []}, {"action": {}}, {"action": None},
            {"explanation": []}, {"explanation": None},
            {"confidence": True}, {"confidence": "0.95"},
            {"confidence": float("nan")}, {"confidence": float("inf")},
            {"confidence": -1}, {"confidence": 2},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(AnalystError):
                parse_decision(self.envelope({**valid, **changes}))
        self.assertEqual(parse_decision(self.envelope(valid)), Decision("block", .95, "Evidencia alta"))

    def test_invalid_provider_envelopes_are_controlled_errors(self):
        for raw in (b"[]", b"null", b'{"choices":[]}', b'{"choices":[null]}',
                    b'{"choices":[{"message":[]}]}', b'{"choices":[{"message":{"content":[]}}]}',
                    self.envelope([]), b"not-json"):
            with self.subTest(raw=raw), self.assertRaises(AnalystError):
                parse_decision(raw)

    def test_outbound_boundary_rejects_extra_fields_and_text_before_network(self):
        settings = Settings("ingest-test", "admin-test", ai_api_key="fake-test-key")
        facts = {
            "category": "possible_brute_force", "failed_attempts": 5,
            "event_count": 5, "window_seconds": 60,
            "seconds_between_first_and_last": 1.2, "distinct_usernames": 1,
        }
        invalid = [
            {**facts, "source_ip": "10.231.37.4"},
            {**facts, "username": "cuenta-canaria"},
            {**facts, "category": "cuenta-canaria"},
            {**facts, "failed_attempts": "5"},
            {**facts, "distinct_usernames": True},
            {**facts, "window_seconds": float("nan")},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with patch("backend.analyst.http.client.HTTPSConnection") as network:
                    with self.assertRaises(AnalystError):
                        ask_model(payload, settings)
                    network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
