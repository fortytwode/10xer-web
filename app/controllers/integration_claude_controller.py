from flask import Blueprint, request, session, redirect, url_for, jsonify, flash
from flask_login import login_required, current_user
import uuid
import os
import requests
import logging
from app.models.user import User
from app.models.token import Token
from bson import ObjectId

logger = logging.getLogger(__name__)
claude_bp = Blueprint("claude_integrations", __name__)

# Load Facebook credentials from environment
FB_CLIENT_ID = os.getenv("FACEBOOK_APP_ID")
FB_CLIENT_SECRET = os.getenv("FACEBOOK_APP_SECRET")
FB_REDIRECT_URI = os.getenv("FACEBOOK_REDIRECT_URI", "https://10xer-web-production.up.railway.app/claude/mcp-auth/callback")

if not FB_CLIENT_ID or not FB_CLIENT_SECRET:
    logger.error("Facebook App ID or Secret not set in environment variables!")

# ---------------- MCP AUTH / Claude OAuth START ----------------
@claude_bp.route("/mcp-auth/authorize")
def mcp_authorize():
    """
    Start OAuth2 PKCE flow for MCP (Claude) or web users.
    """
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state") or uuid.uuid4().hex

    if not client_id or not redirect_uri:
        return jsonify({"error": "Missing client_id or redirect_uri"}), 400

    # Save MCP session params
    session.update({
        "mcp_redirect_uri": redirect_uri,
        "mcp_state": state,
        "mcp_client_id": client_id
    })

    # Generate FB state for OAuth
    fb_state = str(uuid.uuid4())
    session["fb_oauth_state"] = fb_state

    fb_auth_url = (
        f"https://www.facebook.com/v23.0/dialog/oauth?"
        f"client_id={FB_CLIENT_ID}&"
        f"redirect_uri={FB_REDIRECT_URI}&"
        f"scope=ads_read,ads_management,business_management,pages_read_engagement,pages_manage_ads&"
        f"response_type=code&state={fb_state}"
    )

    logger.info(f"Redirecting to Facebook OAuth: {fb_auth_url}")
    return redirect(fb_auth_url)


# ---------------- OAuth CALLBACK ----------------
@claude_bp.route("/mcp-auth/callback")
def mcp_callback():
    """
    Handle Facebook OAuth callback.
    Works for both web users and MCP (Claude) flow.
    """
    error = request.args.get("error")
    code = request.args.get("code")
    state = request.args.get("state")
    stored_fb_state = session.get("fb_oauth_state")

    if error:
        logger.error(f"Facebook OAuth error: {error}")
        return jsonify({"error": f"Facebook OAuth error: {error}"}), 400

    if not code or not state or state != stored_fb_state:
        logger.error(f"Invalid OAuth state. Received: {state}, Expected: {stored_fb_state}")
        return jsonify({"error": "Invalid OAuth state"}), 400

    # Exchange code for Facebook access token
    token_url = "https://graph.facebook.com/v23.0/oauth/access_token"
    params = {
        "client_id": FB_CLIENT_ID,
        "redirect_uri": FB_REDIRECT_URI,
        "client_secret": FB_CLIENT_SECRET,
        "code": code,
    }

    try:
        resp = requests.get(token_url, params=params, timeout=10)
        resp.raise_for_status()
        token_resp = resp.json()
        access_token = token_resp.get("access_token")
        if not access_token:
            raise ValueError("No access token received")
    except Exception as e:
        logger.error(f"Failed to retrieve Facebook token: {e}")
        return jsonify({"error": "Failed to retrieve Facebook token"}), 500

    # Determine if this is MCP flow or normal web flow
    mcp_redirect_uri = session.pop("mcp_redirect_uri", None)
    mcp_state = session.pop("mcp_state", None)

    # Save Facebook token in DB (with MCP code if necessary)
    if mcp_redirect_uri and mcp_state:
        # MCP flow → generate temporary authorization code
        mcp_code = str(uuid.uuid4())
        Token.create(
            user_id=ObjectId(),  # temporary placeholder
            token_type="mcp_code",
            token=mcp_code,
            extra_data={"facebook_access_token": access_token}
        )
        session.pop("fb_oauth_state", None)
        logger.info(f"MCP OAuth completed, redirecting back to Claude: {mcp_redirect_uri}")
        return redirect(f"{mcp_redirect_uri}?code={mcp_code}&state={mcp_state}")
    else:
        # Web user flow → require login
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))

        Token.create(
            user_id=current_user.id,
            token_type="facebook",
            token=access_token
        )

        session.pop("fb_oauth_state", None)
        flash("Facebook integration successful!", "success")
        return redirect(url_for("dashboard.dashboard"))


# ---------------- GET ACCESS TOKEN FOR WEB ----------------
@claude_bp.route("/api/facebook/token", methods=["GET"])
@login_required
def get_facebook_token():
    try:
        token_obj = Token.get_by_user_id_and_type(current_user.id, "facebook")
        if not token_obj:
            return jsonify({"success": False, "message": "No Facebook access token found"}), 404

        return jsonify({
            "success": True,
            "access_token": token_obj.token
        })
    except Exception as e:
        logger.error(f"Error fetching Facebook token for user {current_user.id}: {e}")
        return jsonify({"success": False, "message": "Error retrieving token"}), 500