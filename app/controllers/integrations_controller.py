from flask import Blueprint, render_template, redirect, url_for, request, session, abort, flash
from flask_login import login_required, current_user
from app.models.user import User
from app.models.token import Token
import requests
import os
import uuid
import logging
from flask import jsonify

logger = logging.getLogger(__name__)

integrations_bp = Blueprint("integrations", __name__)

# Use environment variables for sensitive data; fallback to None to force config
FB_CLIENT_ID = os.getenv("FACEBOOK_APP_ID")
FB_CLIENT_SECRET = os.getenv("FACEBOOK_APP_SECRET")
FB_REDIRECT_URI = os.getenv("FACEBOOK_REDIRECT_URI", "http://localhost:8000/integrations/auth/callback")

if not FB_CLIENT_ID or not FB_CLIENT_SECRET:
    logger.error("Facebook App ID or Secret not set in environment variables!")

@integrations_bp.route("/integrations", methods=["GET", "POST"])
@login_required
def integrations():
    user = User.get(current_user.id)
    if request.method == "POST":
        # TODO: Add handling for other integrations or "skip"
        flash("Integration process completed or skipped.", "info")
        return redirect(url_for("dashboard.dashboard"))
    return render_template("integrations.html", user=user)

@integrations_bp.route("/facebook/disconnect", methods=["POST"])
@login_required
def facebook_disconnect():
    try:
        token_obj = Token.get_by_user_id_and_type(current_user.id, "facebook")
        if token_obj:
            Token.collection.delete_one({"_id": token_obj.id})
            logger.info(f"User {current_user.id} disconnected Facebook integration.")
            return jsonify({"message": "Facebook integration disconnected successfully."}), 200
        else:
            return jsonify({"error": "No Facebook integration found to disconnect."}), 404
    except Exception as e:
        logger.error(f"Error disconnecting Facebook integration for user {current_user.id}: {e}")
        return jsonify({"error": "Failed to disconnect Facebook integration."}), 500

@integrations_bp.route("/facebook/connect")
@login_required
def facebook_connect():
    state = str(uuid.uuid4())
    session['fb_oauth_state'] = state

    fb_auth_url = (
        "https://www.facebook.com/v23.0/dialog/oauth?"
        f"client_id={FB_CLIENT_ID}&"
        f"redirect_uri={FB_REDIRECT_URI}&"
        "scope=ads_read,ads_management,business_management,pages_read_engagement,pages_manage_ads&"
        "response_type=code&"
        f"state={state}"
    )
    logger.debug(f"Redirecting to Facebook OAuth URL with state={state}")
    return redirect(fb_auth_url)

@integrations_bp.route("/auth/callback")
@login_required
def facebook_callback():
    error = request.args.get("error")
    if error:
        logger.error(f"Facebook OAuth error: {error}")
        flash(f"Facebook OAuth error: {error}", "danger")
        return render_template("error.html", message=error), 400

    code = request.args.get("code")
    state = request.args.get("state")

    stored_state = session.get('fb_oauth_state')
    if not state or state != stored_state:
        logger.warning(f"Invalid OAuth state. Received: {state}, Expected: {stored_state}")
        abort(400, description="Invalid OAuth state")

    if not code:
        logger.warning("Missing OAuth code in callback")
        flash("Missing OAuth code", "warning")
        return redirect(url_for("integrations.integrations"))

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
        token_response = resp.json()
    except requests.RequestException as e:
        logger.error(f"Exception during token request: {e}")
        flash("Failed to retrieve access token from Facebook", "danger")
        return render_template("error.html", message="Failed to retrieve access token from Facebook"), 500
    except ValueError as e:
        logger.error(f"Invalid JSON response from Facebook token endpoint: {e}")
        flash("Invalid response from Facebook", "danger")
        return render_template("error.html", message="Failed to parse access token response"), 500

    access_token = token_response.get("access_token")
    expires_in = token_response.get("expires_in")

    if not access_token:
        logger.error(f"No access token in response: {token_response}")
        flash("Failed to retrieve access token from Facebook", "danger")
        return render_template("error.html", message="No access token received from Facebook"), 400

    user = User.get(current_user.id)
    if not user:
        logger.error(f"Current user not found with id {current_user.id}")
        abort(404)

    # Save token to tokens table
    Token.create(
        user_id=user.id,
        token_type="facebook",
        token=access_token
    )

    # Clear OAuth state from session after successful auth
    session.pop('fb_oauth_state', None)

    # Generate a session_id for tracking or add to your existing session logic
    session_id = str(uuid.uuid4())
    # TODO: persist session_id mapping if necessary

    redirect_url = url_for("dashboard.dashboard", session_id=session_id)
    logger.info(f"Facebook OAuth callback successful, redirecting to: {redirect_url}")

    flash("Facebook integration successful!", "success")
    return redirect(redirect_url, code=303)
