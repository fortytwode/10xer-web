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

@integrations_bp.route("/api/mcp-auth/authorize")
def mcp_authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")
    
    if not all([client_id, redirect_uri, state]):
        return jsonify({"error": "Missing OAuth parameters"}), 400
    
    # Store params and redirect directly to Facebook OAuth
    session.update({
        'mcp_redirect_uri': redirect_uri,
        'mcp_state': state,
        'mcp_client_id': client_id
    })
    
    fb_state = str(uuid.uuid4())
    session['fb_oauth_state'] = fb_state
    
    fb_auth_url = f"https://www.facebook.com/v23.0/dialog/oauth?client_id={FB_CLIENT_ID}&redirect_uri={FB_REDIRECT_URI}&scope=ads_read,ads_management,business_management&response_type=code&state={fb_state}"
    
    return redirect(fb_auth_url)

# @integrations_bp.route("/api/mcp-auth/authorize")
# def mcp_authorize():
#     logger.info(f"MCP Authorization request received from {request.remote_addr}")
#     logger.info(f"Request args: {dict(request.args)}")
#     logger.info(f"Request headers: {dict(request.headers)}")
    
#     # Get OAuth params from Claude
#     client_id = request.args.get("client_id")
#     redirect_uri = request.args.get("redirect_uri")
#     state = request.args.get("state")
    
#     logger.info(f"OAuth params - client_id: {client_id}, redirect_uri: {redirect_uri}, state: {state}")
    
#     if not client_id or not redirect_uri or not state:
#         logger.error(f"Missing OAuth parameters - client_id: {bool(client_id)}, redirect_uri: {bool(redirect_uri)}, state: {bool(state)}")
#         return jsonify({"error": "Missing OAuth parameters", "details": {
#             "client_id": bool(client_id),
#             "redirect_uri": bool(redirect_uri), 
#             "state": bool(state)
#         }}), 400
    
#     # Check if user is authenticated
#     logger.info(f"User authenticated: {current_user.is_authenticated}")
    
#     if not current_user.is_authenticated:
#         # Store MCP params in session for later
#         session.update({
#             'mcp_redirect_uri': redirect_uri,
#             'mcp_state': state,
#             'mcp_client_id': client_id
#         })
        
#         # Redirect to login with MCP params preserved
#         login_url = url_for('auth.login', 
#                           mcp_redirect=redirect_uri, 
#                           mcp_state=state, 
#                           mcp_client=client_id)
        
#         logger.info(f"Redirecting unauthenticated user to: {login_url}")
#         return redirect(login_url)
    
#     # User is authenticated - start Facebook OAuth flow
#     logger.info("User is authenticated, starting Facebook OAuth flow")
    
#     # Check for Facebook credentials
#     if not FB_CLIENT_ID or not FB_CLIENT_SECRET:
#         logger.error("Facebook credentials not configured")
#         return jsonify({"error": "Facebook integration not configured"}), 500
    
#     session.update({
#         'mcp_redirect_uri': redirect_uri,
#         'mcp_state': state,
#         'mcp_client_id': client_id
#     })
    
#     fb_state = str(uuid.uuid4())
#     session['fb_oauth_state'] = fb_state
    
#     fb_auth_url = (
#         f"https://www.facebook.com/v23.0/dialog/oauth?"
#         f"client_id={FB_CLIENT_ID}&"
#         f"redirect_uri={FB_REDIRECT_URI}&"
#         f"scope=ads_read,ads_management,business_management,pages_read_engagement,pages_manage_ads&"
#         f"response_type=code&"
#         f"state={fb_state}"
#     )
    
#     logger.info(f"Redirecting to Facebook OAuth: {fb_auth_url}")
#     return redirect(fb_auth_url)

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

# @integrations_bp.route("/auth/callback")
# @login_required
# def facebook_callback():
#     error = request.args.get("error")
#     if error:
#         logger.error(f"Facebook OAuth error: {error}")
#         flash(f"Facebook OAuth error: {error}", "danger")
#         return render_template("error.html", message=error), 400

#     code = request.args.get("code")
#     state = request.args.get("state")

#     stored_state = session.get('fb_oauth_state')
#     if not state or state != stored_state:
#         logger.warning(f"Invalid OAuth state. Received: {state}, Expected: {stored_state}")
#         abort(400, description="Invalid OAuth state")

#     if not code:
#         logger.warning("Missing OAuth code in callback")
#         flash("Missing OAuth code", "warning")
#         return redirect(url_for("integrations.integrations"))

#     token_url = "https://graph.facebook.com/v23.0/oauth/access_token"
#     params = {
#         "client_id": FB_CLIENT_ID,
#         "redirect_uri": FB_REDIRECT_URI,
#         "client_secret": FB_CLIENT_SECRET,
#         "code": code,
#     }

#     try:
#         resp = requests.get(token_url, params=params, timeout=10)
#         resp.raise_for_status()
#         token_response = resp.json()
#     except requests.RequestException as e:
#         logger.error(f"Exception during token request: {e}")
#         flash("Failed to retrieve access token from Facebook", "danger")
#         return render_template("error.html", message="Failed to retrieve access token from Facebook"), 500
#     except ValueError as e:
#         logger.error(f"Invalid JSON response from Facebook token endpoint: {e}")
#         flash("Invalid response from Facebook", "danger")
#         return render_template("error.html", message="Failed to parse access token response"), 500

#     access_token = token_response.get("access_token")
#     expires_in = token_response.get("expires_in")

#     if not access_token:
#         logger.error(f"No access token in response: {token_response}")
#         flash("Failed to retrieve access token from Facebook", "danger")
#         return render_template("error.html", message="No access token received from Facebook"), 400

#     user = User.get(current_user.id)
#     if not user:
#         logger.error(f"Current user not found with id {current_user.id}")
#         abort(404)

#     # Save token to tokens table
#     Token.create(
#         user_id=user.id,
#         token_type="facebook",
#         token=access_token
#     )

#     # Clear OAuth state from session after successful auth
#     session.pop('fb_oauth_state', None)

#     # Generate a session_id for tracking or add to your existing session logic
#     session_id = str(uuid.uuid4())
#     # TODO: persist session_id mapping if necessary

#     redirect_url = url_for("dashboard.dashboard", session_id=session_id)
#     logger.info(f"Facebook OAuth callback successful, redirecting to: {redirect_url}")

#     flash("Facebook integration successful!", "success")
#     return redirect(redirect_url, code=303)

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

    # Check if this is part of MCP flow
    mcp_redirect_uri = session.get("mcp_redirect_uri")
    mcp_state = session.get("mcp_state")
    
    if mcp_redirect_uri and mcp_state:
        # This is an MCP authorization flow
        # Generate authorization code for Claude
        mcp_code = str(uuid.uuid4())
        
        # Store MCP authorization code with Facebook token
        Token.create(
            user_id=current_user.id,
            token_type="mcp_code",
            token=mcp_code,
            extra_data={"facebook_access_token": access_token}
        )
        
        # Clear MCP session data
        session.pop("mcp_redirect_uri", None)
        session.pop("mcp_state", None)
        session.pop("mcp_code_challenge", None)
        session.pop("mcp_client_id", None)
        
        # Redirect back to Claude with authorization code
        logger.info(f"MCP OAuth flow completed, redirecting to Claude: {mcp_redirect_uri}")
        return redirect(f"{mcp_redirect_uri}?code={mcp_code}&state={mcp_state}")
    
    else:
        # Regular web app integration flow
        session_id = str(uuid.uuid4())
        redirect_url = url_for("dashboard.dashboard", session_id=session_id)
        logger.info(f"Facebook OAuth callback successful, redirecting to: {redirect_url}")
        
        flash("Facebook integration successful!", "success")
        return redirect(redirect_url, code=303)

@integrations_bp.route("/api/facebook/token", methods=["GET"], endpoint="api_facebook_token")
@login_required
def get_facebook_token():
    try:
        # Fetch token from DB
        print("current_user->", current_user.id)
        token_obj = Token.get_by_user_id_and_type(current_user.id, "facebook")

        if not token_obj:
            return jsonify({
                "success": False,
                "message": "No Facebook access token found."
            }), 404

        return jsonify({
            "success": True,
            "user_id": current_user.id,
            "token_type": "facebook",
            "access_token": token_obj.token
        }), 200

    except Exception as e:
        logger.error(f"Error fetching Facebook token for user {current_user.id}: {e}")
        return jsonify({
            "success": False,
            "message": "Error retrieving token."
        }), 500

