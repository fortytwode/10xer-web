from flask import Flask, jsonify, request, send_from_directory, redirect
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import CollectionInvalid
from flask_login import LoginManager
from sqlalchemy import true
from app.config import Config
from app.models import user
from app.claude_connector_manifest import CLAUDE_CONNECTOR_MANIFEST

from app.models import user, token, user_session  # import token model here too
import os
import requests
from flask import session, redirect

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enable CORS for API routes
    # CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Secure session cookie settings for Claude cross-origin
    app.config.update(
        SECRET_KEY=Config.SECRET_KEY,
        SESSION_COOKIE_SECURE=True,        # Required for HTTPS
        SESSION_COOKIE_SAMESITE="None",    # Needed for cross-origin (Claude -> your server)
        SESSION_COOKIE_HTTPONLY=True
    )
    
    # Enable CORS for /api/* and /mcp-api/* endpoints with open origins
    CORS(app, resources={
        r"/api/*": {"origins": "*"},
        r"/mcp-api/*": {"origins": "*"},
        r"/integrations/*": {"origins": "*"},
        r"/claude/*": {"origins": "*"},
        r"/.well-known/*": {"origins": "*"}
    }, supports_credentials=True)

    # MongoDB setup
    mongo_client = MongoClient(app.config["MONGO_URI"])
    db = mongo_client.get_database("10Xer")

    # Create 'users' collection if not exists (no schema validation here)
    try:
        db.create_collection("users")
        print("Collection 'users' created without schema validation.")
    except CollectionInvalid:
        print("Collection 'users' already exists.")

    # Assign MongoDB users collection to User model
    user.User.collection = db["users"]

    # Create 'tokens' collection if not exists (no schema validation here)
    try:
        db.create_collection("tokens")
        print("Collection 'tokens' created without schema validation.")
    except CollectionInvalid:
        print("Collection 'tokens' already exists.")

    # Assign MongoDB tokens collection to Token model
    token.Token.collection = db["tokens"]


    try:
        db.create_collection("userSessions")
        print("Collection 'userSessions' created without schema validation.")
    except CollectionInvalid:
        print("Collection 'userSessions' already exists.")

    # Assign MongoDB tokens collection to Token model
    user_session.UserSession.collection = db["userSessions"]

    # Flask-Login setup
    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return user.User.get(user_id)

    # Register Blueprints
    from app.controllers.auth_controller import auth_bp
    from app.controllers.dashboard_controller import dashboard_bp
    from app.controllers.integrations_controller import integrations_bp
    from app.controllers.mcp_api import mcp_api  # ✅ Import your SSE API here
    from app.controllers.integration_claude_controller import claude_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(integrations_bp, url_prefix="/integrations")
    app.register_blueprint(mcp_api, url_prefix="/mcp-api")  # Add this line back
    app.register_blueprint(claude_bp, url_prefix="/claude")

    @app.route("/", methods=["GET"])
    def welcome():
        return jsonify({"message": "Welcome to the MongoDB-powered API"}), 200
    

    # Add this route at the app level (not in a blueprint)
    # @app.route('/.well-known/oauth-authorization-server', methods=["GET"])
    # def oauth_discovery():
    #     return jsonify({
    #         "authorization_endpoint": "https://10xer-web-production.up.railway.app/claude/mcp-auth/authorize",
    #         "token_endpoint": "https://10xer-web-production.up.railway.app/mcp-api/token",
    #         "registration_uri": "https://10xer-web-production.up.railway.app/claude/manifest"
    #     })
    
    # Alias route for Claude (it probes here as part of OAuth discovery)
    @app.route('/.well-known/oauth-authorization-server/claude/manifest', methods=["GET"])
    def oauth_manifest_alias():
        return jsonify(CLAUDE_CONNECTOR_MANIFEST)

    @app.route('/claude/manifest', methods=["GET", "POST"])
    def claude_manifest():
        return jsonify(CLAUDE_CONNECTOR_MANIFEST)
    
    # @app.route('/claude/testing_manifest.json', methods=["GET", "POST"])
    # def claude_testing_manifest():
    #     return jsonify({
    #     "dxt_version": "0.1",
    #     "name": "10xer",
    #     "display_name": "10xer MCP Live Server",
    #     "version": "0.1.0",
    #     "description": "Extension to connect Claude with the 10xer MCP Server for real-time event streaming.",
    #     "long_description": "The 10xer MCP Server extension enables integration with the 10xer MCP Server, allowing Claude to communicate via server-sent events (SSE) and proxy commands through a live Node.js server.",
    #     "author": {
    #         "name": "10xer MCP",
    #         "email": "mahmadimran1110@gmail.com",
    #         "url": "https://10xer-web-production.up.railway.app/"
    #     },
    #     "repository": {
    #         "type": "git",
    #         "url": "https://10xer-web-production.up.railway.app/"
    #     },
    #     "homepage": "https://10xer-web-production.up.railway.app/",
    #     "icon": "favicon.png",
    #     "auth": {
    #         "type": "redirect"
    #     },
    #     "connect_uri": "https://10xer-web-production.up.railway.app/claude/mcp-auth/authorize",
    #     "server": {
    #         "type": "node",
    #         "entry_point": "src/index.js",
    #         "mcp_config": {
    #         "command": "node",
    #         "args": [
    #             "${__dirname}/src/index.js",
    #             "10xer MCP Server",
    #             "https://10xer-web-production.up.railway.app/mcp-api/sse",
    #             "${user_config.api_key}"
    #         ],
    #         "env": {
    #             "SERVER_NAME": "10xer MCP Server",
    #             "SSE_URL": "https://10xer-web-production.up.railway.app/mcp-api/sse",
    #             "API_KEY": "${user_config.api_key}"
    #         }
    #         }
    #     },
    #     "user_config": {
    #         "api_key": {
    #         "type": "string",
    #         "title": "10xer MCP Live Server API Key",
    #         "description": "Enter your API key generated from the 10xer MCP Server integration page.",
    #         "sensitive": true,
    #         "required": true
    #         }
    #     },
    #     "tools": [],
    #     "keywords": ["stdio", "sse", "mcp", "proxy"],
    #     "license": "MIT",
    #     "compatibility": {
    #         "claude_desktop": ">=0.10.0",
    #         "platforms": ["darwin", "win32", "linux"],
    #         "runtimes": {
    #         "node": ">=16.0.0"
    #         }
    #     }
    #     })

    @app.route('/claude/testing_manifest.json', methods=["GET", "POST"])
    def claude_testing_manifest():
        data = {
            "dxt_version": "0.1",
            "name": "10xer",
            "display_name": "10xer MCP Live Server",
            "version": "0.1.0",
            "description": "Extension to connect Claude with the 10xer MCP Server for real-time event streaming.",
            "long_description": "The 10xer MCP Server extension enables integration with the 10xer MCP Server, allowing Claude to communicate via server-sent events (SSE) and proxy commands through a live Node.js server.",
            "author": {
                "name": "10xer MCP",
                "email": "mahmadimran1110@gmail.com",
                "url": "https://10xer-web-production.up.railway.app/"
            },
            "repository": {
                "type": "git",
                "url": "https://10xer-web-production.up.railway.app/"
            },
            "homepage": "https://10xer-web-production.up.railway.app/",
            "icon": "favicon.png",
            "auth": {
                "type": "redirect"
            },
            "connect_uri": "https://10xer-web-production.up.railway.app/claude/mcp-auth/authorize"
        }
        return jsonify(data)
    
    FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
    FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET")

    
    # @app.route("/claude/mcp-auth/authorize", methods=["GET"])
    # def mcp_authorize():
    #     fb_oauth_url = (
    #         "https://www.facebook.com/v16.0/dialog/oauth?"
    #         f"client_id={FACEBOOK_APP_ID}"
    #         "&response_type=code"
    #         f"&redirect_uri=https://claude.ai/mcp-api/oauth/callback"
    #         "&scope=ads_read,ads_management,business_management"
    #     )
    #     return redirect(fb_oauth_url)

    
    @app.route("/mcp-api/token", methods=["POST"])
    def token_exchange():
        data = request.get_json(force=True)
        # if not data or "code" not in data:
        #     return jsonify({"error": "Missing code"}), 400

        # code = data["code"]

        # # Exchange code for Facebook access token
        # fb_token_response = requests.get(
        #     "https://graph.facebook.com/v16.0/oauth/access_token",
        #     params={
        #         "client_id": FACEBOOK_APP_ID,
        #         "client_secret": FACEBOOK_APP_SECRET,
        #         "redirect_uri": "https://claude.ai/mcp-api/oauth/callback",
        #         "code": code
        #     }
        # )
        # token_data = fb_token_response.json()

        # # Save token in MongoDB (optional)
        # if "access_token" in token_data:
        #     token.Token.create(
        #         user_id="CLAUDE_USER_ID",  # optional placeholder if you want to save
        #         token_type="facebook",
        #         token=token_data["access_token"],
        #         extra_data=token_data
        #     )

        # # Return JSON (Claude MCP popup closes automatically)
        # return jsonify({
        #     "access_token": token_data.get("access_token"),
        #     "expires_in": token_data.get("expires_in"),
        #     "refresh_token": token_data.get("refresh_token")
        # })


    @app.route('/.well-known/oauth-authorization-server/claude/testing_manifest.json', methods=["GET"])
    def well_known_auth_server():
        return jsonify({
            "issuer": "https://10xer-web-production.up.railway.app",
            "authorization_endpoint": "https://10xer-web-production.up.railway.app/claude/mcp-auth/authorize",
            "token_endpoint": "https://10xer-web-production.up.railway.app/mcp-api/token",
            "scopes_supported": ["ads_read"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"]
        })
    @app.route('/.well-known/oauth-protected-resource/claude/testing_manifest.json', methods=["GET"])
    def well_known_protected_resource():
        return jsonify({
            "issuer": "https://10xer-web-production.up.railway.app",
            "introspection_endpoint": "https://10xer-web-production.up.railway.app/mcp-api/introspect"
        })
        
    @app.route('/images/<path:filename>')
    def images(filename):
        return send_from_directory('images', filename)

    return app

