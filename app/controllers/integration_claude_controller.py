from flask import Blueprint, redirect, request, jsonify
import os
import requests
from app.models import token
from app.claude_connector_manifest import CLAUDE_CONNECTOR_MANIFEST

claude_bp = Blueprint("claude_bp", __name__)

FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET")

# Manifest Endpoint (Claude reads this)
@claude_bp.route("/manifest", methods=["GET", "POST"])
def claude_manifest():
    return jsonify(CLAUDE_CONNECTOR_MANIFEST)

# Authorization Endpoint (redirects user to Facebook)
@claude_bp.route("/mcp-auth/authorize", methods=["GET"])
def mcp_authorize():
    fb_oauth_url = (
        f"https://www.facebook.com/v16.0/dialog/oauth?"
        f"client_id={FACEBOOK_APP_ID}"
        "&response_type=code"
        "&redirect_uri=https://claude.ai/mcp-api/oauth/callback"
        "&scope=ads_read,ads_management,business_management"
    )
    return redirect(fb_oauth_url)

# Token Endpoint (Claude POSTs here after authorization)
@claude_bp.route("/mcp-api/token", methods=["POST"])
def token_exchange():
    data = request.get_json(force=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing code"}), 400

    code = data["code"]

    # Exchange code for Facebook access token
    fb_token_response = requests.get(
        "https://graph.facebook.com/v16.0/oauth/access_token",
        params={
            "client_id": FACEBOOK_APP_ID,
            "client_secret": FACEBOOK_APP_SECRET,
            "redirect_uri": "https://claude.ai/mcp-api/oauth/callback",
            "code": code
        }
    )
    token_data = fb_token_response.json()

    # Save token in MongoDB (optional)
    if "access_token" in token_data:
        token.Token.create(
            user_id="CLAUDE_USER",  # optional
            token_type="facebook",
            token=token_data["access_token"],
            extra_data=token_data
        )

    # Return JSON to Claude (popup closes automatically)
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in"),
        "refresh_token": token_data.get("refresh_token")
    })