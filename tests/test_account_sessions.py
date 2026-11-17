"""Exercise the normal Flask factory and account workflows with an in-memory Mongo boundary."""
import os
import socket
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId


class Collection:
    def __init__(self):
        self.rows = {}

    def find_one(self, query, sort=None):
        matches = [row for row in self.rows.values() if all(
            row.get(field) != value["$ne"] if isinstance(value, dict) else row.get(field) == value
            for field, value in query.items())]
        if sort:
            matches.sort(key=lambda row: row[sort[0][0]], reverse=True)
        return dict(matches[0]) if matches else None

    def update_one(self, query, update):
        row = self.find_one(query)
        if row:
            self.rows[row["_id"]].update(update["$set"])
        return SimpleNamespace(modified_count=int(bool(row)))

    def find_one_and_update(self, query, update, upsert, return_document):
        assert upsert and return_document
        row = self.rows.setdefault(query["_id"], {**query, **update["$setOnInsert"]})
        row.update(update["$set"])
        return dict(row)

    def delete_many(self, query):
        matches = [k for k, row in self.rows.items() if all(row[field] == val for field, val in query.items())]
        for key in matches:
            del self.rows[key]
        return SimpleNamespace(deleted_count=len(matches))


class AccountSessions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.enterClassContext(patch.dict(os.environ, {
            "MONGO_URI": "mongodb://example.invalid/fixture", "SECRET_KEY": "synthetic-test-signing-key",
            "FACEBOOK_APP_ID": "fixture", "FACEBOOK_APP_SECRET": "fixture", "SENDGRID_API_KEY": "fixture",
        }, clear=True))
        cls.enterClassContext(patch.object(socket, "getaddrinfo", side_effect=AssertionError("offline")))
        cls.enterClassContext(patch.object(socket, "create_connection", side_effect=AssertionError("offline")))
        import app
        cls.factory = staticmethod(app.create_app)

    def setUp(self):
        self.collections = {name: Collection() for name in ("users", "tokens", "userSessions")}
        with patch("app.MongoClient") as client:
            db = client.return_value.get_database.return_value
            db.__getitem__.side_effect = self.collections.__getitem__
            self.app = self.factory()
        self.app.testing = True
        self.client = self.app.test_client()
        self.owner, self.other = ObjectId(), ObjectId()
        for owner, key in ((self.owner, "fixture-account-a"), (self.other, "fixture-account-b")):
            self.collections["users"].rows[owner] = {"_id": owner, "email": "person@example.test",
                                                    "api_key": key, "api_key_version": 2}
            token = ObjectId()
            self.collections["tokens"].rows[token] = {"_id": token, "user_id": owner,
                "created_at": datetime.now(timezone.utc), "token_type": "facebook", "token": "fixture-meta-" + key, "extra_data": {}}
        self.headers = {"Authorization": "Bearer fixture-account-a"}

    def sign_in(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.owner)
            session["_fresh"] = True
            session["verified_login_user"] = str(self.owner)

    def test_account_bound_registration_and_read(self):
        route = "/mcp-api/"
        registration = {"user_id": str(self.other), "session_id": "fixture-session", "server_ip": "fixture",
                        "organization_id": "shared-org"}
        for _ in range(2):
            self.assertEqual(self.client.post(route + "save_user_session", headers=self.headers,
                                              json=registration).status_code, 200)
        self.assertEqual(len(self.collections["userSessions"].rows), 1)
        legacy_id = ObjectId()
        self.collections["userSessions"].rows[legacy_id] = {"_id": legacy_id, "user_id": self.other,
            "organization_id": "shared-org", "session_id": "fixture-session"}
        for endpoint, query in (("get_latest_session_by_session_id", {"session_id": "fixture-session"}),
                                ("get_latest_session_by_org_id", {"organization_id": "shared-org"})):
            self.assertEqual(self.client.get(route + endpoint, headers=self.headers,
                                             query_string=query).json["user_id"], str(self.owner))
            self.assertEqual(self.client.get(route + endpoint, query_string=query,
                headers={"Authorization": "Bearer fixture-account-b"}).status_code, 404)
            self.assertEqual(self.client.get(route + endpoint, query_string=query).status_code, 401)
        for endpoint in ("facebook_token", "facebook_token_by_user"):
            self.assertEqual(self.client.get(route + endpoint, headers=self.headers).json["facebook_access_token"],
                             "fixture-meta-fixture-account-a")
            self.assertEqual(self.client.get(route + endpoint).status_code, 401)

    def test_owner_upgrades_legacy_key_after_interactive_login(self):
        account = self.collections["users"].rows[self.owner]
        del account["api_key_version"]
        self.assertEqual(self.client.get("/mcp-api/facebook_token", headers=self.headers).status_code, 403)
        self.sign_in()
        first = self.client.get("/dashboard/dashboard")
        self.assertEqual(first.status_code, 200)
        upgraded = account["api_key"]
        self.assertIn(upgraded.encode(), first.data)
        self.assertGreaterEqual(len(upgraded), 43)
        self.assertEqual(self.client.get("/dashboard/dashboard").status_code, 200)
        self.assertEqual(account["api_key"], upgraded)
        self.assertEqual(self.client.get("/mcp-api/facebook_token",
            headers={"Authorization": "Bearer " + upgraded}).status_code, 200)

    def test_google_sign_in_requires_verified_email_and_browser_state(self):
        from urllib.parse import parse_qs, urlparse

        token_response = SimpleNamespace(json=lambda: {"access_token": "fixture-google", "id_token": "fixture-id"})
        for verified in (False, True):
            location = self.client.get("/login/google").location
            state = parse_qs(urlparse(location).query)["state"][0]
            with patch("app.controllers.auth_controller.requests.post", return_value=token_response), patch(
                "app.controllers.auth_controller.id_token.verify_oauth2_token",
                return_value={"email": "person@example.test", "email_verified": verified},
            ), patch("app.models.user.User.verify_email"):
                response = self.client.get("/api/auth/google", query_string={"code": "fixture", "state": state})
            self.assertEqual(response.status_code, 302 if verified else 403)
            with self.client.session_transaction() as session:
                self.assertEqual(bool(session.get("verified_login_user")), verified)

    def test_older_cookie_requires_current_sign_in(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.owner)
            session["_fresh"] = True
        self.assertEqual(self.client.get("/dashboard/dashboard").status_code, 401)
        self.assertEqual(self.client.get("/integrations/integrations").status_code, 401)

    def test_sse_call_uses_verified_account(self):
        with patch("app.controllers.mcp_api.facebook_list_ad_accounts_function", return_value={"ok": True}) as graph:
            response = self.client.post("/mcp-api/sse", headers=self.headers, json={"tool": "facebook_list_ad_accounts"})
            self.assertEqual(response.json, {"ok": True})
            graph.assert_called_once_with("fixture-meta-fixture-account-a")
        self.assertEqual(self.client.post("/mcp-api/sse", json={}).status_code, 401)

    def test_signed_in_sync_and_disconnect(self):
        self.sign_in()
        for path in ("integrations", "api/facebook/token"):
            response = self.client.get("/integrations/" + path, headers={"Origin": "https://example.test"})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        with self.client.session_transaction() as session:
            proof = session["integration_csrf"]
        self.assertIn(proof.encode(), self.client.get("/integrations/integrations").data)
        headers = {"X-CSRF-Token": proof}
        sync = "/integrations/forward_token_to_10xer"
        self.assertEqual(self.client.post(sync, json={"organization_id": "my-org"}).status_code, 403)
        self.assertEqual(self.client.post(sync, headers=headers, json={"organization_id": "my-org"}).status_code, 200)
        registered = next(iter(self.collections["userSessions"].rows.values()))
        self.assertEqual(registered["user_id"], self.owner)
        self.assertTrue(registered["verified_owner"])
        tokens = self.collections["tokens"].rows
        extra = ObjectId()
        tokens[extra] = {**next(iter(tokens.values())), "_id": extra}
        disconnect = "/integrations/facebook/disconnect"
        self.assertEqual(self.client.post(disconnect).status_code, 403)
        self.assertEqual(self.client.post(disconnect, headers=headers).status_code, 200)
        self.assertEqual({row["user_id"] for row in tokens.values()}, {self.other})
        self.assertEqual(self.client.get("/mcp-api/facebook_token", headers=self.headers).status_code, 404)
