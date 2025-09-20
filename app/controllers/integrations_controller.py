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

@integrations_bp.route("/forward_token_to_10xer", methods=["POST"])
@login_required
def forward_token():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON data"}), 400

    organization_id= data.get("organization_id")
    print("Received Organization ID ->", organization_id)
    print("current_user->", current_user.id)
    token_obj = Token.get_by_user_id_and_type(current_user.id, "facebook")
    if not token_obj:
        return jsonify({"error": "No token found"}), 404
    
    # Or directly get the 'session' cookie value
    session_cookie = request.cookies.get('session')
    print("Session cookie:", session_cookie)

    # Build headers including 'session-id' with the full session cookie value (including the "session=" prefix)
    # If you want to include the key, prefix it; otherwise just send the cookie value
    session_id_header_value = f"session={session_cookie}" if session_cookie else ""

    headers = {
        "Authorization": "Bearer YOUR_SHARED_SECRET",
        "session-id": session_id_header_value
    }

    response = requests.post(
        "https://10xer-production.up.railway.app/trigger-token-fetch",
        json={"access_token": token_obj.token, "user_id": current_user.id, "organization_id": organization_id},
        headers=headers,
        timeout=360
    )
    print("response->", response)
    if response.status_code == 200:
        return jsonify({"status": "Token forwarded"})
    else:
        return jsonify({"error": "Failed to forward token"}), 500
    

@integrations_bp.route("/enter_organization", methods=["GET", "POST"])
def enter_organization():
    if request.method == "GET":
        # Serve the HTML form for user input
        return render_template("enter_organization.html")

    # POST: receive organization_id JSON, save in session
    data = request.get_json()
    if not data or "organization_id" not in data:
        return jsonify({"success": False, "message": "Missing organization_id"}), 400

    organization_id = data["organization_id"]
    session["organization_id"] = organization_id  # Store for later
    print(f"Stored organization_id: {organization_id} for user {current_user.id}")
    return jsonify({"success": True, "message": f"Organization ID {organization_id} stored"})

@integrations_bp.route("/get_organization_id", methods=["GET"])
def get_organization_id():
    print("session->", session)
    # API endpoint to fetch stored organization_id from session
    org_id = session.get("organization_id")
    if not org_id:
        return jsonify({"success": False, "message": "Organization ID not set"}), 404
    return jsonify({"success": True, "organization_id": org_id})

# @integrations_bp.route("/forward_token_to_10xer", methods=["POST"])
# @login_required
# def forward_token():
#     print("current_user->", current_user.id)
#     token_obj = Token.get_by_user_id_and_type(current_user.id, "facebook")
#     print("token_obj->", token_obj.token)
#     if not token_obj:
#         return jsonify({"error": "No token found"}), 404
#     response = requests.post(
#         "https://10xer-production.up.railway.app/trigger-token-fetch",
#         json={"access_token": token_obj.token, "user_id": current_user.id},
#         headers={"Authorization": "Bearer YOUR_SHARED_SECRET"},
#         timeout=5
#     )
#     print("response->", response)
#     if response.status_code == 200:
#         return jsonify({"status": "Token forwarded"})
#     else:
#         return jsonify({"error": "Failed to forward token"}), 500

@integrations_bp.route("/api/mcp-auth/authorize")
def mcp_authorize():
    logger.info(f"MCP Authorization request from {request.remote_addr}")
    logger.info(f"Args: {dict(request.args)}")
    
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")
    
    if not all([client_id, redirect_uri, state]):
        logger.error("Missing OAuth parameters")
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
    
    logger.info(f"Redirecting to Facebook OAuth: {fb_auth_url}")
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

# @integrations_bp.route("/auth/callback")
# def facebook_callback():  # Remove @login_required decorator
#     logger.info(f"Facebook callback received from {request.remote_addr}")
    
#     error = request.args.get("error")
#     if error:
#         logger.error(f"Facebook OAuth error: {error}")
#         # For MCP flow, return JSON instead of flash/template
#         mcp_redirect_uri = session.get("mcp_redirect_uri")
#         if mcp_redirect_uri:
#             return jsonify({"error": f"Facebook OAuth error: {error}"}), 400
#         flash(f"Facebook OAuth error: {error}", "danger")
#         return render_template("error.html", message=error), 400

#     code = request.args.get("code")
#     state = request.args.get("state")

#     stored_state = session.get('fb_oauth_state')
#     if not state or state != stored_state:
#         logger.warning(f"Invalid OAuth state. Received: {state}, Expected: {stored_state}")
#         mcp_redirect_uri = session.get("mcp_redirect_uri")
#         if mcp_redirect_uri:
#             return jsonify({"error": "Invalid OAuth state"}), 400
#         abort(400, description="Invalid OAuth state")

#     if not code:
#         logger.warning("Missing OAuth code in callback")
#         mcp_redirect_uri = session.get("mcp_redirect_uri")
#         if mcp_redirect_uri:
#             return jsonify({"error": "Missing OAuth code"}), 400
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
#         mcp_redirect_uri = session.get("mcp_redirect_uri")
#         if mcp_redirect_uri:
#             return jsonify({"error": "Failed to retrieve access token from Facebook"}), 500
#         flash("Failed to retrieve access token from Facebook", "danger")
#         return render_template("error.html", message="Failed to retrieve access token from Facebook"), 500
#     except ValueError as e:
#         logger.error(f"Invalid JSON response from Facebook token endpoint: {e}")
#         mcp_redirect_uri = session.get("mcp_redirect_uri")
#         if mcp_redirect_uri:
#             return jsonify({"error": "Invalid response from Facebook"}), 500
#         flash("Invalid response from Facebook", "danger")
#         return render_template("error.html", message="Failed to parse access token response"), 500

#     access_token = token_response.get("access_token")
#     expires_in = token_response.get("expires_in")

#     if not access_token:
#         logger.error(f"No access token in response: {token_response}")
#         mcp_redirect_uri = session.get("mcp_redirect_uri")
#         if mcp_redirect_uri:
#             return jsonify({"error": "No access token received from Facebook"}), 400
#         flash("Failed to retrieve access token from Facebook", "danger")
#         return render_template("error.html", message="No access token received from Facebook"), 400

#     # Check if this is part of MCP flow
#     mcp_redirect_uri = session.get("mcp_redirect_uri")
#     mcp_state = session.get("mcp_state")
    
#     if mcp_redirect_uri and mcp_state:
#         # This is an MCP authorization flow - handle without authenticated user
#         logger.info("Processing MCP OAuth flow")
        
#         # Generate authorization code for Claude
#         mcp_code = str(uuid.uuid4())
        
#         # Store MCP authorization code with Facebook token (without user_id for now)
#         # Token.create(
#         #     user_id="temp_mcp_user",  # Temporary placeholder
#         #     token_type="mcp_code",
#         #     token=mcp_code,
#         #     extra_data={"facebook_access_token": access_token}
#         # )

#         from bson import ObjectId
#         Token.create(
#             user_id=ObjectId(),  # Generate a temporary ObjectId
#             token_type="mcp_code", 
#             token=mcp_code,
#             extra_data={"facebook_access_token": access_token}
#         )
        
#         # Clear MCP session data
#         session.pop("mcp_redirect_uri", None)
#         session.pop("mcp_state", None)
#         session.pop("mcp_code_challenge", None)
#         session.pop("mcp_client_id", None)
#         session.pop('fb_oauth_state', None)
        
#         # Redirect back to Claude with authorization code
#         logger.info(f"MCP OAuth flow completed, redirecting to Claude: {mcp_redirect_uri}")
#         return redirect(f"{mcp_redirect_uri}?code={mcp_code}&state={mcp_state}")
    
#     else:
#         # Regular web app integration flow - requires authenticated user
#         if not current_user.is_authenticated:
#             logger.error("Regular flow requires authenticated user")
#             return redirect(url_for("auth.login"))
            
#         user = User.get(current_user.id)
#         if not user:
#             logger.error(f"Current user not found with id {current_user.id}")
#             abort(404)

#         # Save token to tokens table
#         Token.create(
#             user_id=user.id,
#             token_type="facebook",
#             token=access_token
#         )

#         # Clear OAuth state from session after successful auth
#         session.pop('fb_oauth_state', None)
        
#         session_id = str(uuid.uuid4())
#         redirect_url = url_for("dashboard.dashboard", session_id=session_id)
#         logger.info(f"Facebook OAuth callback successful, redirecting to: {redirect_url}")
        
#         flash("Facebook integration successful!", "success")
#         return redirect(redirect_url, code=303)

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
# @login_required
def get_facebook_token():
    try:
        auth_header = request.headers.get("Authorization")
        print("auth_header->", auth_header)

        if auth_header:
            # If Authorization header exists, use it as token
            # Support both 'Bearer <token>' and bare token
            if auth_header.startswith("Bearer "):
                token = auth_header[len("Bearer "):].strip()
            else:
                token = auth_header.strip()

            token_obj = Token.get_by_token_and_type(token, "facebook")
            print("token_obj->", token_obj)

            if not token_obj:
                return jsonify({
                    "success": False,
                    "message": "Invalid or expired token."
                }), 401

            return jsonify({
                "success": True,
                "user_id": str(token_obj['user_id']),
                "token_type": token_obj['token_type'],
                "access_token": token_obj['token']
            }), 200

        else:
            # No Authorization header, fallback to old logic using current_user.id
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
        logger.error(f"Error fetching Facebook token: {e}")
        return jsonify({
            "success": False,
            "message": "Error retrieving token."
        }), 500

