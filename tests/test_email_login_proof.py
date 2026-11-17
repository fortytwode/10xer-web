"""Offline regression tests for the email login challenge."""

import contextlib
import importlib
import io
import os
import socket
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from flask import Flask
from flask_login import LoginManager, current_user, login_required


ROOT = Path(__file__).resolve().parents[1]


class FakeCollection:
    def __init__(self):
        self.documents = []

    def insert_one(self, document):
        self.documents.append(document)
        return types.SimpleNamespace(inserted_id=document["_id"])

    def find_one(self, query):
        for document in self.documents:
            if all(
                document.get(key) > value["$gt"] if isinstance(value, dict) and "$gt" in value
                else document.get(key) == value
                for key, value in query.items()
            ):
                return document
        return None

    def update_one(self, query, update):
        document = self.find_one(query)
        if document is None:
            return types.SimpleNamespace(modified_count=0)
        document.update(update["$set"])
        return types.SimpleNamespace(modified_count=1)

    def find_one_and_update(self, query, update):
        document = self.find_one(query)
        if document is None:
            return None
        previous = dict(document)
        document.update(update["$set"])
        return previous


class EmailLoginProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Avoid app/__init__.py, which reads dotenv and constructs Mongo-backed services.
        cls.module_patch = patch.dict(sys.modules, {
            name: types.ModuleType(name) for name in ("app", "app.models", "app.utils", "app.controllers")
        })
        cls.module_patch.start()
        for name, relative in (("app", "app"), ("app.models", "app/models"),
                               ("app.utils", "app/utils"), ("app.controllers", "app/controllers")):
            sys.modules[name].__path__ = [str(ROOT / relative)]
        cls.env_patch = patch.dict(os.environ, {"SENDGRID_API_KEY": "synthetic-sendgrid-key"}, clear=True)
        cls.env_patch.start()
        cls.socket_patch = patch.object(socket, "socket", side_effect=AssertionError("network disabled"))
        cls.dns_patch = patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS disabled"))
        cls.socket_patch.start()
        cls.dns_patch.start()
        cls.import_output = io.StringIO()
        with contextlib.redirect_stdout(cls.import_output):
            cls.user_module = importlib.import_module("app.models.user")
            cls.email_module = importlib.import_module("app.utils.email_utils")
            cls.auth = importlib.import_module("app.controllers.auth_controller")
            cls.integrations = importlib.import_module("app.controllers.integrations_controller")
        cls.provider_patch = patch.object(cls.auth.requests, "post", side_effect=AssertionError("provider disabled"))
        cls.provider_patch.start()
        cls.google_patch = patch.object(cls.auth.id_token, "verify_oauth2_token",
                                        side_effect=AssertionError("Google SDK disabled"))
        cls.google_patch.start()
        cls.sendgrid_patch = patch.object(cls.email_module.SendGridAPIClient, "send",
                                          side_effect=AssertionError("SendGrid SDK disabled"))
        cls.sendgrid_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.sendgrid_patch.stop()
        cls.google_patch.stop()
        cls.provider_patch.stop()
        cls.dns_patch.stop()
        cls.socket_patch.stop()
        cls.env_patch.stop()
        cls.module_patch.stop()
        for name in ("app.models.user", "app.models.token", "app.utils.email_utils",
                     "app.controllers.auth_controller", "app.controllers.integrations_controller"):
            sys.modules.pop(name, None)

    def setUp(self):
        self.collection = FakeCollection()
        self.user_module.User.collection = self.collection
        self.sent = []
        self.mail_patch = patch.object(self.auth, "send_verification_email",
                                       side_effect=lambda email, token: self.sent.append((email, token)))
        self.mail_patch.start()
        self.app = Flask(__name__, template_folder=str(ROOT / "app/templates"))
        self.app.config.update(SECRET_KEY="synthetic-session-secret", TESTING=True)
        login_manager = LoginManager()
        login_manager.init_app(self.app)

        @login_manager.user_loader
        def load_user(user_id):
            return self.user_module.User.get(user_id)

        self.app.register_blueprint(self.auth.auth_bp)
        self.app.register_blueprint(self.integrations.integrations_bp, url_prefix="/integrations")

        @self.app.route("/dashboard/dashboard", endpoint="dashboard.dashboard")
        @login_required
        def dashboard():
            return f"dashboard:{current_user.email}"

        self.client = self.app.test_client()

    def tearDown(self):
        self.mail_patch.stop()
        self.user_module.User.collection = None

    def add_user(self, email="person@example.test", verified=True):
        user = self.user_module.User.create(email)
        if verified:
            self.user_module.User.verify_email(email)
        return user

    def assert_anonymous(self):
        with self.client.session_transaction() as session:
            self.assertNotIn("_user_id", session)
        self.assertEqual(self.client.get("/dashboard/dashboard").status_code, 401)

    def callback(self, email, token, extra=None):
        return self.client.get("/users/api/auth/callback/email",
                               query_string={"email": email, "token": token, **(extra or {})})

    def test_verified_user_requires_fresh_email_proof(self):
        self.add_user()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            response = self.client.post("/login", data={"email": "person@example.test"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlparse(response.location).path, "/users/verify-request")
        self.assertEqual(len(self.sent), 1)
        self.assert_anonymous()
        self.assertTrue(self.sent[0][1] not in output.getvalue(), "Issued token reached output")

    def test_new_and_unverified_users_receive_challenge_without_sign_in(self):
        self.add_user("unverified@example.test", verified=False)
        for email in ("unverified@example.test", "new@example.test"):
            with self.subTest(email=email):
                response = self.client.post("/login", data={"email": email})
                self.assertEqual(urlparse(response.location).path, "/users/verify-request")
                self.assertEqual(self.sent[-1][0], email)
                self.assert_anonymous()
        email, token = self.sent[-1]
        callback = self.callback(email, token)
        self.assertEqual(urlparse(callback.location).path, "/dashboard/dashboard")
        self.assertTrue(self.collection.find_one({"email": email})["isEmailVerify"])

    def test_valid_callback_uses_real_signed_session_and_replay_fails(self):
        self.add_user()
        self.client.post("/login", data={"email": "person@example.test"})
        email, token = self.sent[-1]
        bad = self.callback(email, "wrong-token")
        self.assertEqual(urlparse(bad.location).path, "/login")
        self.assert_anonymous()
        good = self.callback(email, token)
        self.assertEqual(urlparse(good.location).path, "/dashboard/dashboard")
        with self.client.session_transaction() as session:
            self.assertEqual(session.get("_user_id"), str(self.collection.documents[0]["_id"]))
        self.assertEqual(self.client.get("/dashboard/dashboard").data,
                         b"dashboard:person@example.test")
        self.client.get("/logout")
        replay = self.callback(email, token)
        self.assertEqual(urlparse(replay.location).path, "/login")
        self.assert_anonymous()

    def test_expired_token_cannot_authenticate(self):
        self.add_user()
        self.client.post("/login", data={"email": "person@example.test"})
        email, token = self.sent[-1]
        self.collection.documents[0]["email_token_expires"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        response = self.callback(email, token)
        self.assertEqual(urlparse(response.location).path, "/login")
        self.assert_anonymous()

    def test_mcp_continuation_waits_for_proof_and_ignores_callback_query(self):
        self.add_user()
        self.client.get("/login?mcp_redirect=https%3A%2F%2Fclaude.ai%2Fmcp-api%2Foauth%2Fcallback&mcp_state=state-a&mcp_client=client-a")
        response = self.client.post("/login?mcp_redirect=https%3A%2F%2Fclaude.ai%2Fmcp-api%2Foauth%2Fcallback&mcp_state=state-a&mcp_client=client-a",
                                    data={"email": "person@example.test"})
        self.assertEqual(urlparse(response.location).path, "/users/verify-request")
        self.assert_anonymous()
        email, token = self.sent[-1]
        callback = self.callback(email, token, {"mcp_redirect": "https://attacker.example", "mcp_state": "attacker"})
        parsed = urlparse(callback.location)
        self.assertEqual(parsed.netloc, "www.facebook.com")
        self.assertEqual(parsed.path, "/v23.0/dialog/oauth")
        state = parse_qs(parsed.query)["state"][0]
        with self.client.session_transaction() as session:
            self.assertEqual(session["mcp_redirect_uri"], self.auth.MCP_REDIRECT_URI)
            self.assertEqual(session["mcp_state"], "state-a")
            self.assertEqual(session["mcp_client_id"], "client-a")
            self.assertEqual(session["fb_oauth_state"], state)
            self.assertEqual(session.get("_user_id"), str(self.collection.documents[0]["_id"]))

    def test_synthetic_sendgrid_key_is_not_printed_at_import(self):
        self.assertTrue("synthetic-sendgrid-key" not in self.import_output.getvalue(),
                        "Configured key reached output")

    def test_verification_email_preserves_special_characters_in_email(self):
        from html import unescape
        import re

        email = "person+tag&other@example.test"
        self.add_user(email)
        self.client.post("/login", data={"email": email})
        _, token = self.sent[-1]
        with patch.object(self.email_module, "LIVE_APP_URL", "https://app.example.test"), \
             patch.object(self.email_module, "Mail") as mail, \
             patch.object(self.email_module, "SendGridAPIClient"):
            self.email_module.send_verification_email(email, token)
        content = mail.call_args.kwargs["html_content"]
        link = unescape(re.search(r'href="([^"]+)"', content).group(1))
        parsed = urlparse(link)
        self.assertEqual(parse_qs(parsed.query), {"token": [token], "email": [email]})
        response = self.client.get(parsed.path + "?" + parsed.query)
        self.assertEqual(urlparse(response.location).path, "/dashboard/dashboard")

    def test_overlapping_challenge_cannot_resume_another_mcp_attempt(self):
        self.add_user("first@example.test")
        self.add_user("second@example.test")
        for email, state in (("first@example.test", "first"), ("second@example.test", "second")):
            self.client.post("/login", query_string={
                "mcp_redirect": self.auth.MCP_REDIRECT_URI, "mcp_state": state,
                "mcp_client": "client-a",
            }, data={"email": email})
        email, token = self.sent[0]
        with self.client.session_transaction() as session:
            self.assertNotIn(token, repr(dict(session)))
        response = self.callback(email, token)
        self.assertEqual(urlparse(response.location).path, "/dashboard/dashboard")
        with self.client.session_transaction() as session:
            self.assertNotIn("fb_oauth_state", session)
            for key in ("mcp_redirect_uri", "mcp_state", "mcp_client_id", "mcp_email_challenge"):
                self.assertNotIn(key, session)

    def test_ordinary_login_clears_pending_mcp_and_ignores_callback_parameters(self):
        self.add_user()
        self.client.post("/login", query_string={
            "mcp_redirect": self.auth.MCP_REDIRECT_URI, "mcp_state": "pending",
            "mcp_client": "client-a",
        }, data={"email": "person@example.test"})
        self.client.post("/login", data={"email": "person@example.test"})
        email, token = self.sent[-1]
        response = self.callback(email, token, {
            "mcp_redirect": "https://client.example/done", "mcp_state": "untrusted",
        })
        self.assertEqual(urlparse(response.location).path, "/dashboard/dashboard")
        with self.client.session_transaction() as session:
            for key in ("mcp_redirect_uri", "mcp_state", "mcp_client_id", "mcp_email_challenge"):
                self.assertNotIn(key, session)

    def test_email_token_is_consumed_by_one_conditional_database_update(self):
        self.add_user()
        self.client.post("/login", data={"email": "person@example.test"})
        email, token = self.sent[-1]
        with patch.object(self.collection, "find_one_and_update", wraps=self.collection.find_one_and_update) as consume, \
             patch.object(self.user_module.User, "get_by_email_token", side_effect=AssertionError("non-atomic lookup")):
            response = self.callback(email, token)
        self.assertEqual(urlparse(response.location).path, "/dashboard/dashboard")
        query, update = consume.call_args.args
        self.assertEqual(query["email"], email)
        self.assertEqual(query["email_token"], token)
        self.assertIn("$gt", query["email_token_expires"])
        self.assertEqual(update["$set"], {"email_token": None, "email_token_expires": None})
        self.assertIsNone(self.user_module.User.consume_email_token(email, token))

    def test_unregistered_mcp_redirect_is_rejected_before_email_challenge(self):
        self.add_user()
        for uri in ("https://attacker.example", "https://claude.ai.attacker.example/mcp-api/oauth/callback",
                    self.auth.MCP_REDIRECT_URI + "?next=untrusted"):
            with self.subTest(uri=uri):
                response = self.client.post("/login", query_string={"mcp_redirect": uri, "mcp_state": "state"},
                                            data={"email": "person@example.test"})
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.sent, [])
        self.assert_anonymous()

    def test_facebook_callback_rejects_stale_unregistered_redirect_before_provider(self):
        self.add_user()
        self.client.post("/login", data={"email": "person@example.test"})
        self.callback(*self.sent[-1])
        with self.client.session_transaction() as session:
            session.update(fb_oauth_state="facebook-state", mcp_redirect_uri="https://attacker.example",
                           mcp_state="mcp-state")
        with patch.object(self.integrations.requests, "get", side_effect=AssertionError("provider disabled")) as provider:
            response = self.client.get("/integrations/auth/callback?state=facebook-state&code=synthetic-code")
        self.assertEqual(response.status_code, 400)
        provider.assert_not_called()

    def test_registered_mcp_callback_preserves_state_as_one_query_parameter(self):
        self.add_user()
        state = "state&code=other"
        self.client.post("/login", query_string={"mcp_redirect": self.auth.MCP_REDIRECT_URI, "mcp_state": state},
                         data={"email": "person@example.test"})
        self.callback(*self.sent[-1])
        with self.client.session_transaction() as session:
            facebook_state = session["fb_oauth_state"]
        fake_response = types.SimpleNamespace(raise_for_status=lambda: None,
                                               json=lambda: {"access_token": "synthetic-facebook-token"})
        with patch.object(self.integrations.requests, "get", return_value=fake_response), \
             patch.object(self.integrations.Token, "create") as create:
            response = self.client.get("/integrations/auth/callback", query_string={
                "state": facebook_state, "code": "synthetic-code",
            })
        parsed = urlparse(response.location)
        self.assertEqual(parsed._replace(query="").geturl(), self.auth.MCP_REDIRECT_URI)
        query = parse_qs(parsed.query)
        self.assertEqual(query["state"], [state])
        self.assertEqual(query["code"], [create.call_args.kwargs["token"]])


if __name__ == "__main__":
    unittest.main()
