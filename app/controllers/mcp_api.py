from flask import Blueprint, request, jsonify, Response, stream_with_context, redirect
from flask.sessions import SecureCookieSessionInterface
from app import create_app
from app.utils.decode_session import decode_flask_session
from app.models.user import User
from app.models.token import Token
import uuid
import time
import requests
import logging
from functools import wraps
import os
from app.models.user_session import UserSession

logger = logging.getLogger(__name__)

mcp_api = Blueprint("mcp_api", __name__)

FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET")

def handle_facebook_api_error(response):
    """Standardize Facebook API error handling"""
    try:
        if response.status_code == 400:
            error_data = response.json()
            if error_data.get('error', {}).get('code') == 190:
                return jsonify({"error": "Facebook token expired", "code": "TOKEN_EXPIRED"}), 401
        
        return jsonify({
            "error": "Facebook API error",
            "status_code": response.status_code,
            "details": response.text
        }), response.status_code
    except:
        # If we can't parse the error response, return a generic error
        return jsonify({
            "error": "Facebook API error",
            "status_code": response.status_code,
            "details": "Unable to parse error details"
        }), response.status_code

def mcp_auth_required(f):
    """Decorator to authenticate MCP requests using Bearer token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid authorization header"}), 401
        
        token = auth_header.split(' ')[1]
        
        # Find MCP access token in database
        mcp_token_obj = Token.get_by_token_and_type(token, "mcp_access")
        if not mcp_token_obj:
            return jsonify({"error": "Invalid access token"}), 401
        
        # Set user context for the request
        request.mcp_user_id = mcp_token_obj.user_id
        request.facebook_token = mcp_token_obj.extra_data.get("facebook_access_token")
        
        return f(*args, **kwargs)
    return decorated_function

@mcp_api.route("/token", methods=["GET", "POST"])
def token_exchange():
    """
    Exchange Facebook code for access token and redirect back to Claude
    """
    data = request.args if request.method=="GET" else request.get_json(force=True)
    code = data.get("code")
    user_id = data.get("user_id")  # optional if you know the user

    if not code:
        return jsonify({"error": "Missing code"}), 400

    # Exchange code with Facebook
    fb_response = requests.get(
        "https://graph.facebook.com/v16.0/oauth/access_token",
        params={
            "client_id": FACEBOOK_APP_ID,
            "client_secret": FACEBOOK_APP_SECRET,
            "redirect_uri": "https://claude.ai/mcp-api/oauth/callback",
            "code": code
        }
    )

    fb_data = fb_response.json()
    access_token = fb_data.get("access_token")
    expires_in = fb_data.get("expires_in", 3600)

    if not access_token:
        return jsonify({"error": "Facebook token exchange failed", "details": fb_data}), 400

    # Save token in MongoDB if user_id is provided
    if user_id:
        Token.create(user_id=user_id, token_type="facebook", token=access_token, extra_data=fb_data)

    # ✅ Redirect popup to Claude to close it
    redirect_url = f"https://claude.ai/mcp-api/oauth/callback?access_token={access_token}&token_type=Bearer&expires_in={expires_in}"
    return redirect(redirect_url)

@mcp_api.route("/facebook_token", methods=["GET"])
def get_facebook_token():
    """Legacy endpoint for API key authentication"""
    auth_header = request.headers.get("Authorization")
    logger.debug(f"AUTH HEADER RECEIVED: {auth_header}")
    
    if not auth_header:
        return jsonify({
            "success": False,
            "message": "Missing 'Authorization' header."
        }), 401

    parts = auth_header.split()
    logger.debug(f"Header parts: {parts}")
    
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({
            "success": False,
            "message": "Invalid Authorization header format. Expected 'Bearer <API_KEY>'"
        }), 401
    
    api_key = parts[1]
    logger.debug(f"API Key extracted: {api_key}")
    
    user = User.get_by_api_key(api_key)
    logger.debug(f"User fetched: {user}")
    
    if not user:
        return jsonify({
            "success": False,
            "message": "Invalid or expired API key."
        }), 403

    token_obj = Token.get_by_user_id_and_type(user.id, "facebook")
    logger.debug(f"Token object fetched: {token_obj}")

    if token_obj:
        logger.debug(f"Token ID: {token_obj.id}")
        logger.debug(f"User ID: {token_obj.user_id}")
        logger.debug(f"Token Type: {token_obj.token_type}")
        logger.debug(f"Access Token: {token_obj.token}")   
    else:
        logger.debug("No token object found.")

    if not token_obj:
        return jsonify({
            "success": False,
            "message": "Facebook token not found for user."
        }), 404

    return jsonify({
        "success": True,
        "facebook_access_token": token_obj.token
    }), 200

# @mcp_api.route("/facebook_token_by_user", methods=["GET"])
# def get_facebook_token_by_user():
#     user_id = request.args.get("userId")
#     print(f"User ID received from query: {user_id}")

#     if not user_id:
#         return jsonify({
#             "success": False,
#             "message": "Missing 'userId' query parameter."
#         }), 400

#     user = User.get(user_id)  # Use existing method
#     print(f"User fetched: {user}")

#     if not user:
#         return jsonify({
#             "success": False,
#             "message": "User not found."
#         }), 404

#     token_obj = Token.get_by_user_id_and_type(user.id, "facebook")
#     print(f"Token object fetched: {token_obj}")

#     if token_obj:
#         print(f"Token ID: {token_obj.id}")
#         print(f"User ID: {token_obj.user_id}")
#         print(f"Token Type: {token_obj.token_type}")
#         print(f"Access Token: {token_obj.token}")
#     else:
#         print("No token object found.")

#     if not token_obj:
#         return jsonify({
#             "success": False,
#             "message": "Facebook token not found for user."
#         }), 404

#     return jsonify({
#         "success": True,
#         "facebook_access_token": token_obj.token
#     }), 200

# Your API route
@mcp_api.route("/facebook_token_by_user", methods=["GET"])
def get_facebook_token_by_user():
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        return jsonify({"success": False, "message": "Missing session cookie"}), 400

    session_data = decode_flask_session(session_cookie, create_app())
    user_id = session_data.get("_user_id")
    print("Decoded session data:", session_data)

    if not user_id:
        return jsonify({"success": False, "message": "Invalid or expired session"}), 401

    user = User.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    token_obj = Token.get_by_user_id_and_type(user.id, "facebook")
    if not token_obj:
        return jsonify({"success": False, "message": "Facebook token not found for user."}), 404

    return jsonify({
        "success": True,
        "facebook_access_token": token_obj.token
    }), 200

# Get the server's public IP
def get_server_public_ip():
    try:
        ip = requests.get('https://api.ipify.org').text.strip()
        return ip
    except Exception as e:
        return f"Error: {e}"

# Save or update user session
# @mcp_api.route('/save_user_session', methods=['POST'])
# def save_user_session():
#     data = request.get_json()
#     if not data:
#         return jsonify({"success": False, "message": "Invalid JSON data"}), 400

#     user_id = data.get("user_id")
#     session_id = data.get("session_id")
#     server_ip = get_server_public_ip()
#     print("Server Public IP ->", server_ip)

#     if not all([user_id, session_id, server_ip]):
#         return jsonify({"success": False, "message": "Missing required data"}), 400

#     try:
#         UserSession.save_or_update(user_id, session_id, server_ip)
#     except Exception as e:
#         return jsonify({"success": False, "message": f"Error saving session: {str(e)}"}), 500

#     return jsonify({"success": True, "message": "Session saved", "server_ip": server_ip})
# Get latest session by IP
# @mcp_api.route('/get_latest_session_by_ip', methods=['GET'])
# def get_latest_session_by_ip():
#     server_ip = get_server_public_ip()
#     print("Server Public IP ->", server_ip)

#     if not server_ip:
#         return jsonify({"success": False, "message": "Missing or invalid server IP"}), 400

#     try:
#         session = UserSession.get_latest_session_by_ip(server_ip)
#     except Exception as e:
#         return jsonify({"success": False, "message": f"Error fetching session: {str(e)}"}), 500

#     if not session:
#         return jsonify({"success": False, "message": "No session found for this IP"}), 404

#     return jsonify({
#         "success": True,
#         "session_id": session.session_id,
#         "user_id": str(session.user_id),
#         "server_ip": server_ip
#     })

@mcp_api.route('/save_user_session', methods=['POST'])
def save_user_session():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON data"}), 400

    user_id = data.get("user_id")
    session_id = data.get("session_id")
    server_ip = data.get("server_ip")  # <- get from client now
    print("Received Server IP ->", server_ip)
    organization_id= data.get("organization_id")
    print("Received Organization ID ->", organization_id)

    if not all([user_id, session_id, server_ip]):
        return jsonify({"success": False, "message": "Missing required data"}), 400

    try:
        UserSession.save_or_update(user_id, session_id, server_ip, organization_id)
    except Exception as e:
        return jsonify({"success": False, "message": f"Error saving session: {str(e)}"}), 500

    return jsonify({"success": True, "message": "Session saved", "server_ip": server_ip, "organization_id": organization_id})

@mcp_api.route('/get_latest_session_by_org_id', methods=['GET'])
def get_latest_session_by_org_id():
    # server_ip = request.args.get('server_ip')
    # if not server_ip:
    #     return jsonify({"success": False, "message": "Missing server_ip query parameter"}), 400
    organization_id = request.args.get('organization_id')
    if not organization_id:
        return jsonify({"success": False, "message": "Missing organization_id query parameter"}), 400

    try:
        session = UserSession.get_latest_session_by_org_id(organization_id)
    except Exception as e:
        return jsonify({"success": False, "message": f"Error fetching session: {str(e)}"}), 500

    if not session:
        return jsonify({"success": False, "message": "No organization_id found"}), 404

    return jsonify({
        "success": True,
        "session_id": session.session_id,
        "user_id": str(session.user_id),
        "organization_id": organization_id
    })

@mcp_api.route('/get_latest_session_by_session_id', methods=['GET'])
def get_latest_session_by_session_id():
    session_id = request.args.get('session_id')
    if not session_id:
        return jsonify({"success": False, "message": "Missing session_id in query parameter"}), 400

    try:
        session = UserSession.get_by_session_id(session_id)
    except Exception as e:
        return jsonify({"success": False, "message": f"Error fetching session: {str(e)}"}), 500

    if not session:
        return jsonify({"success": False, "message": "No session found with that session_id"}), 404

    return jsonify({
        "success": True,
        "session_id": session.session_id,
        "user_id": str(session.user_id),
        "organization_id": str(session.organization_id)
    })

# Save or update user session
# @mcp_api.route('/save_user_session', methods=['POST'])
# def save_user_session():
#     data = request.get_json()
#     if not data:
#         return jsonify({"success": False, "message": "Invalid JSON data"}), 400

#     user_id = data.get("user_id")
#     session_id = data.get("session_id")
#     ip_address = request.remote_addr

#     if not all([user_id, session_id, ip_address]):
#         return jsonify({"success": False, "message": "Missing required data"}), 400

#     existing = UserSession.query.filter_by(session_id=session_id).first()

#     if existing:
#         existing.user_id = user_id
#         existing.ip_address = ip_address
#         existing.updated_at = datetime.utcnow()
#     else:
#         new_session = UserSession(
#             user_id=user_id,
#             session_id=session_id,
#             ip_address=ip_address
#         )
#         db.session.add(new_session)

#     db.session.commit()

#     return jsonify({"success": True, "message": "Session saved"})


# # Get latest session by IP
# @mcp_api.route('/get_latest_session_by_ip', methods=['GET'])
# def get_latest_session_by_ip():
#     ip_address = request.remote_addr

#     session = (
#         UserSession.query.filter_by(ip_address=ip_address)
#         .order_by(UserSession.updated_at.desc())
#         .first()
#     )

#     if not session:
#         return jsonify({"success": False, "message": "No session found for this IP"}), 404

#     return jsonify({
#         "success": True,
#         "session_id": session.session_id,
#         "user_id": session.user_id
#     })
# Add these missing implementations to your mcp_api.py file

@mcp_api.route("/tools/facebook_get_adset_details", methods=["POST"])
@mcp_auth_required
def facebook_get_adset_details():
    """Get detailed information about a specific ad set"""
    try:
        request_data = request.get_json()
        adset_id = request_data.get("adset_id")
        fields = request_data.get("fields", ["id", "name", "status", "daily_budget", "lifetime_budget", "targeting", "optimization_goal"])
        
        if not adset_id:
            return jsonify({"error": "Missing required parameter: adset_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Call Facebook Graph API
        url = f"https://graph.facebook.com/v18.0/{adset_id}"
        params = {
            "access_token": access_token,
            "fields": ",".join(fields)
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
            return handle_facebook_api_error(response)
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_adset_details: {e}")
        return jsonify({"error": "Internal server error"}), 500

@mcp_api.route("/tools/facebook_get_creative_asset_url_by_ad_id", methods=["POST"])
@mcp_auth_required
def facebook_get_creative_asset_url_by_ad_id():
    """Get creative asset URLs and details for a specific ad"""
    try:
        request_data = request.get_json()
        ad_id = request_data.get("ad_id")
        
        if not ad_id:
            return jsonify({"error": "Missing required parameter: ad_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # First get the ad's creative ID
        ad_url = f"https://graph.facebook.com/v18.0/{ad_id}"
        ad_params = {
            "access_token": access_token,
            "fields": "creative{id,name,object_story_spec,image_url,video_id,body,title,call_to_action_type,thumbnail_url}"
        }
        
        ad_response = requests.get(ad_url, params=ad_params)
        
        if ad_response.status_code != 200:
            return handle_facebook_api_error(ad_response)
        
        ad_data = ad_response.json()
        creative_data = ad_data.get("creative", {})
        
        # Extract asset URLs from the creative data
        assets = {
            "ad_id": ad_id,
            "creative_id": creative_data.get("id"),
            "creative_name": creative_data.get("name"),
            "image_url": creative_data.get("image_url"),
            "thumbnail_url": creative_data.get("thumbnail_url"),
            "video_id": creative_data.get("video_id"),
            "body": creative_data.get("body"),
            "title": creative_data.get("title"),
            "call_to_action_type": creative_data.get("call_to_action_type"),
            "object_story_spec": creative_data.get("object_story_spec")
        }
        
        return jsonify({
            "success": True,
            "data": assets
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_creative_asset_url_by_ad_id: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Updated facebook_get_adaccount_insights with all parameters from manifest
@mcp_api.route("/tools/facebook_get_adaccount_insights", methods=["POST"])
@mcp_auth_required
def facebook_get_adaccount_insights():
    """Get performance insights for ad accounts, campaigns, or ads"""
    try:
        request_data = request.get_json()
        act_id = request_data.get("act_id")
        fields = request_data.get("fields", [])
        level = request_data.get("level", "account")
        date_preset = request_data.get("date_preset", "last_30d")
        time_range = request_data.get("time_range")
        breakdowns = request_data.get("breakdowns", [])
        filtering = request_data.get("filtering", [])
        
        if not act_id or not fields:
            return jsonify({"error": "Missing required parameters: act_id and fields"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Build Facebook Graph API URL
        url = f"https://graph.facebook.com/v18.0/{act_id}/insights"
        params = {
            "access_token": access_token,
            "fields": ",".join(fields),
            "level": level
        }
        
        # Add date parameters - prioritize time_range over date_preset
        if time_range and 'since' in time_range and 'until' in time_range:
            params["time_range"] = time_range
        else:
            params["date_preset"] = date_preset
        
        # Add optional parameters
        if breakdowns:
            params["breakdowns"] = ",".join(breakdowns)
        
        if filtering:
            params["filtering"] = filtering
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
            return handle_facebook_api_error(response)
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_adaccount_insights: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Updated facebook_get_ad_creatives with limit cap from manifest
@mcp_api.route("/tools/facebook_get_ad_creatives", methods=["POST"])
@mcp_auth_required
def facebook_get_ad_creatives():
    """Get creative assets and performance data for ads"""
    try:
        request_data = request.get_json()
        act_id = request_data.get("act_id")
        limit = request_data.get("limit", 25)
        
        if not act_id:
            return jsonify({"error": "Missing required parameter: act_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Call Facebook Graph API
        url = f"https://graph.facebook.com/v18.0/{act_id}/adcreatives"
        params = {
            "access_token": access_token,
            "fields": "id,name,object_story_spec,image_url,video_id,body,title,call_to_action_type,thumbnail_url",
            "limit": min(limit, 100)  # Cap at 100 as per manifest
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
            return handle_facebook_api_error(response)
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_ad_creatives: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Updated facebook_get_activities_by_adaccount with all parameters
@mcp_api.route("/tools/facebook_get_activities_by_adaccount", methods=["POST"])
@mcp_auth_required
def facebook_get_activities_by_adaccount():
    """Get activity logs for a specific ad account"""
    try:
        request_data = request.get_json()
        act_id = request_data.get("act_id")
        since = request_data.get("since")
        until = request_data.get("until")
        limit = request_data.get("limit", 25)
        
        if not act_id:
            return jsonify({"error": "Missing required parameter: act_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Call Facebook Graph API
        url = f"https://graph.facebook.com/v18.0/{act_id}/activities"
        params = {
            "access_token": access_token,
            "fields": "event_type,event_time,object_id,object_name,object_type,translated_event_type,actor_name",
            "limit": min(limit, 100)  # Cap at 100 as per manifest
        }
        
        # Add date filters if provided
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
            return handle_facebook_api_error(response)
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_activities_by_adaccount: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Updated facebook_get_details_of_ad_account to use standardized error handling
@mcp_api.route("/tools/facebook_get_details_of_ad_account", methods=["POST"])
@mcp_auth_required
def facebook_get_details_of_ad_account():
    """Get detailed information about a specific ad account"""
    try:
        request_data = request.get_json()
        act_id = request_data.get("act_id")
        fields = request_data.get("fields", ["id", "name", "account_status", "currency", "balance", "amount_spent"])
        
        if not act_id:
            return jsonify({"error": "Missing required parameter: act_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Call Facebook Graph API
        url = f"https://graph.facebook.com/v18.0/{act_id}"
        params = {
            "access_token": access_token,
            "fields": ",".join(fields)
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
            return handle_facebook_api_error(response)
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_details_of_ad_account: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Updated facebook_get_campaign_details to use standardized error handling
@mcp_api.route("/tools/facebook_get_campaign_details", methods=["POST"])
@mcp_auth_required
def facebook_get_campaign_details():
    """Get detailed information about a specific campaign"""
    try:
        request_data = request.get_json()
        campaign_id = request_data.get("campaign_id")
        fields = request_data.get("fields", ["id", "name", "objective", "status", "daily_budget", "lifetime_budget", "created_time"])
        
        if not campaign_id:
            return jsonify({"error": "Missing required parameter: campaign_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        url = f"https://graph.facebook.com/v18.0/{campaign_id}"
        params = {
            "access_token": access_token,
            "fields": ",".join(fields)
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
            return handle_facebook_api_error(response)
        
        return jsonify({
            "success": True,
            "data": response.json()
        })
        
    except Exception as e:
        logger.error(f"Error in facebook_get_campaign_details: {e}")
        return jsonify({"error": "Internal server error"}), 500

@mcp_api.route("/sse", methods=["GET", "POST"])
def sse_handler():
    """Handle SSE connections and Claude tool calls"""
    if request.method == "GET":
        # Handle browser/server-sent-events connection
        auth_header = request.headers.get("Authorization")
        logger.debug(f"SSE AUTH HEADER RECEIVED: {auth_header}")
        
        if not auth_header:
            return jsonify({
                "success": False,
                "message": "Missing 'Authorization' header."
            }), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "success": False,
                "message": "Invalid Authorization header format. Expected 'Bearer <API_KEY>'"
            }), 401
        
        api_key = parts[1]
        user = User.get_by_api_key(api_key)
        if not user:
            return jsonify({
                "success": False,
                "message": "Invalid or expired API key."
            }), 403
        
        session_id = str(uuid.uuid4())

        def event_stream():
            message = f"/mcp-api/messages?sessionId={session_id}"
            yield f"data: {message}\n\n"
            while True:
                message = f"/mcp-api/messages?sessionId={session_id}"
                yield f"data: {message}\n\n"
                time.sleep(15)

        return Response(stream_with_context(event_stream()), mimetype='text/event-stream')

    elif request.method == "POST":
        # Handle Claude tool call
        user_id = request.headers.get("X-User-ID")
        user_email = request.headers.get("X-User-Email")

        if not user_id or not user_email:
            return jsonify({
                "success": False,
                "message": "Missing Claude headers: X-User-ID or X-User-Email"
            }), 401

        data = request.json or {}
        tool = data.get("tool")
        input_data = data.get("input", {})

        logger.info(f"Claude Request - User: {user_email}, Tool: {tool}, Input: {input_data}")

        # Map tool names to handler functions
        if tool == "facebook_list_ad_accounts":
            user = User.get_by_claude_id(user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            
            # Fetch Facebook access token
            token_obj = Token.get_by_user_id_and_type(user.id, "facebook")
            if not token_obj:
                return jsonify({"success": False, "error": "Facebook not connected"}), 403
            
            result = facebook_list_ad_accounts_function(token_obj.token)
            return jsonify(result)
        
        # Handle other tools here
        elif tool == "facebook_get_adaccount_insights":
            user = User.get_by_claude_id(user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            
            token_obj = Token.get_by_user_id_and_type(user.id, "facebook")
            if not token_obj:
                return jsonify({"success": False, "error": "Facebook not connected"}), 403
            
            # You'd need to implement this function similar to facebook_list_ad_accounts_function
            # result = facebook_get_adaccount_insights_function(token_obj.token, input_data)
            # return jsonify(result)
            return jsonify({"success": False, "error": "Tool not implemented yet"}), 501
        
        # If no tool matches, return error
        return jsonify({"success": False, "error": f"Unknown tool: {tool}"}), 400
    
    # This should never be reached, but just in case
    return jsonify({"success": False, "error": "Invalid request method"}), 405


def facebook_list_ad_accounts_function(access_token: str) -> dict:
    """Helper function for Facebook ad accounts API call"""
    url = "https://graph.facebook.com/v18.0/me/adaccounts"
    params = {
        "fields": "name,account_status,account_id",
        "access_token": access_token
    }

    response = requests.get(url, params=params)

    if response.status_code != 200:
        logger.error(f"Facebook API error: {response.status_code} - {response.text}")
        return {
            "success": False,
            "error": "Failed to fetch ad accounts from Facebook",
            "status_code": response.status_code,
            "details": response.text
        }

    data = response.json()
    return {
        "success": True,
        "ad_accounts": data.get("data", [])
    }

@mcp_api.route("/tools/facebook_list_ad_accounts", methods=["POST"])
def facebook_list_ad_accounts():
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    access_token = auth_header.split("Bearer ")[1]

    result = facebook_list_ad_accounts_function(access_token)

    return jsonify(result)