from flask import Blueprint, request, session, jsonify, redirect
import uuid
import hashlib
import base64
from app.models.token import Token
from bson import ObjectId
import logging

logger = logging.getLogger(__name__)

claude_bp = Blueprint("claude_integrations", __name__, url_prefix="/claude")

# ---------------- PKCE Helpers ----------------
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(uuid.uuid4().bytes).rstrip(b"=").decode("utf-8")
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode("utf-8")
    return code_verifier, code_challenge

# ---------------- MCP Authorization ----------------
@claude_bp.route("/mcp-auth/authorize")
def mcp_authorize():
    """
    Claude calls this endpoint to start OAuth2 PKCE flow.
    We generate code_verifier and code_challenge and redirect user to Facebook OAuth.
    """
    code_verifier, code_challenge = generate_pkce_pair()
    session["claude_code_verifier"] = code_verifier

    redirect_uri = request.args.get("redirect_uri")  # Claude callback
    state = request.args.get("state") or uuid.uuid4().hex
    client_id = request.args.get("client_id")

    if not redirect_uri or not client_id:
        return jsonify({"error": "Missing redirect_uri or client_id"}), 400

    # Save MCP session params
    session.update({
        "mcp_redirect_uri": redirect_uri,
        "mcp_state": state,
        "mcp_client_id": client_id
    })

    # Redirect to Facebook OAuth
    fb_state = str(uuid.uuid4())
    session["fb_oauth_state"] = fb_state

    FB_CLIENT_ID = "YOUR_FB_APP_ID"  # replace with environment variable or config
    FB_REDIRECT_URI = "https://10xer-web-production.up.railway.app/claude/mcp-auth/callback"

    fb_auth_url = (
        f"https://www.facebook.com/v23.0/dialog/oauth?"
        f"client_id={FB_CLIENT_ID}&"
        f"redirect_uri={FB_REDIRECT_URI}&"
        f"scope=ads_read,ads_management,business_management&"
        f"response_type=code&state={fb_state}"
    )

    logger.info(f"Redirecting to Facebook OAuth: {fb_auth_url}")
    return redirect(fb_auth_url)

# ---------------- OAuth Callback ----------------
@claude_bp.route("/mcp-auth/callback")
def mcp_callback():
    """
    Facebook redirects here after user authorizes.
    We exchange code for access token and generate MCP auth code for Claude.
    """
    error = request.args.get("error")
    if error:
        logger.error(f"Facebook OAuth error: {error}")
        return jsonify({"error": f"Facebook OAuth error: {error}"}), 400

    code = request.args.get("code")
    state = request.args.get("state")
    stored_state = session.get("fb_oauth_state")

    if not code or not state or state != stored_state:
        logger.error(f"Invalid OAuth state. Received: {state}, Expected: {stored_state}")
        return jsonify({"error": "Invalid OAuth state"}), 400

    # Exchange code for access token (simulate or call Facebook)
    FB_CLIENT_ID = "YOUR_FB_APP_ID"
    FB_CLIENT_SECRET = "YOUR_FB_APP_SECRET"
    FB_REDIRECT_URI = "https://10xer-web-production.up.railway.app/claude/mcp-auth/callback"

    import requests
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

    # Generate MCP authorization code for Claude
    mcp_code = str(uuid.uuid4())
    Token.create(
        user_id=ObjectId(),  # Temporary placeholder
        token_type="mcp_code",
        token=mcp_code,
        extra_data={"facebook_access_token": access_token}
    )

    # Retrieve redirect_uri and state from session
    redirect_uri = session.pop("mcp_redirect_uri", None)
    mcp_state = session.pop("mcp_state", None)
    session.pop("fb_oauth_state", None)

    if not redirect_uri or not mcp_state:
        return jsonify({"error": "Missing MCP redirect data"}), 500

    # Redirect back to Claude
    return redirect(f"{redirect_uri}?code={mcp_code}&state={mcp_state}")