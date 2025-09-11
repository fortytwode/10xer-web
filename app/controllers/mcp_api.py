from flask import Blueprint, request, jsonify, Response, stream_with_context
from app.models.user import User
from app.models.token import Token
import uuid
import time
import requests
import logging
from functools import wraps

logger = logging.getLogger(__name__)

mcp_api = Blueprint("mcp_api", __name__, url_prefix="/mcp-api")

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

@mcp_api.route("/token", methods=["POST"])
def mcp_token_exchange():
    """Exchange MCP authorization code for access token"""
    try:
        request_data = request.get_json()
        code = request_data.get("code")
        
        if not code:
            return jsonify({"error": "Missing authorization code"}), 400
        
        # Find the MCP code token in database
        mcp_token_obj = Token.get_by_token_and_type(code, "mcp_code")
        if not mcp_token_obj:
            return jsonify({"error": "Invalid authorization code"}), 401
        
        # Get the associated Facebook token
        facebook_token = mcp_token_obj.extra_data.get("facebook_access_token")
        if not facebook_token:
            return jsonify({"error": "No associated Facebook token found"}), 401
        
        # Generate access token for MCP
        access_token = str(uuid.uuid4())
        
        # Store MCP access token
        Token.create(
            user_id=mcp_token_obj.user_id,
            token_type="mcp_access",
            token=access_token,
            extra_data={"facebook_access_token": facebook_token}
        )
        
        # Clean up the authorization code
        Token.collection.delete_one({"_id": mcp_token_obj.id})
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600  # 1 hour
        })
        
    except Exception as e:
        logger.error(f"Error in MCP token exchange: {e}")
        return jsonify({"error": "Token exchange failed"}), 500

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

@mcp_api.route("/tools/facebook_list_ad_accounts", methods=["POST"])
@mcp_auth_required
def facebook_list_ad_accounts():
    """List all Facebook ad accounts accessible to the user"""
    try:
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Call Facebook Graph API
        url = "https://graph.facebook.com/v18.0/me/adaccounts"
        params = {
            "access_token": access_token,
            "fields": "id,name,account_status,currency,balance,amount_spent"
        }
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except requests.RequestException as e:
        logger.error(f"Facebook API error: {e}")
        return jsonify({"error": "Failed to fetch ad accounts"}), 500
    except Exception as e:
        logger.error(f"Error in facebook_list_ad_accounts: {e}")
        return jsonify({"error": "Internal server error"}), 500

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
        breakdowns = request_data.get("breakdowns", [])
        
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
            "level": level,
            "date_preset": date_preset
        }
        
        if breakdowns:
            params["breakdowns"] = ",".join(breakdowns)
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except requests.RequestException as e:
        logger.error(f"Facebook API error: {e}")
        return jsonify({"error": "Failed to fetch insights"}), 500
    except Exception as e:
        logger.error(f"Error in facebook_get_adaccount_insights: {e}")
        return jsonify({"error": "Internal server error"}), 500

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
            "fields": "id,name,object_story_spec,image_url,video_id,body,title,call_to_action_type",
            "limit": limit
        }
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except requests.RequestException as e:
        logger.error(f"Facebook API error: {e}")
        return jsonify({"error": "Failed to fetch ad creatives"}), 500
    except Exception as e:
        logger.error(f"Error in facebook_get_ad_creatives: {e}")
        return jsonify({"error": "Internal server error"}), 500

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
        response.raise_for_status()
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data
        })
        
    except requests.RequestException as e:
        logger.error(f"Facebook API error: {e}")
        return jsonify({"error": "Failed to fetch ad account details"}), 500
    except Exception as e:
        logger.error(f"Error in facebook_get_details_of_ad_account: {e}")
        return jsonify({"error": "Internal server error"}), 500

@mcp_api.route("/tools/facebook_get_activities_by_adaccount", methods=["POST"])
@mcp_auth_required
def facebook_get_activities_by_adaccount():
    """Get activity logs for a specific ad account"""
    try:
        request_data = request.get_json()
        act_id = request_data.get("act_id")
        
        if not act_id:
            return jsonify({"error": "Missing required parameter: act_id"}), 400
        
        access_token = request.facebook_token
        if not access_token:
            return jsonify({"error": "No Facebook access token found"}), 401
        
        # Call Facebook Graph API
        url = f"https://graph.facebook.com/v18.0/{act_id}/activities"
        params = {
            "access_token": access_token,
            "fields": "event_type,event_time,object_id,object_name,object_type,translated_event_type,actor_name"
        }
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        return jsonify({
            "success": True,
            "data": data.get("data", []),
            "paging": data.get("paging", {})
        })
        
    except requests.RequestException as e:
        logger.error(f"Facebook API error: {e}")
        return jsonify({"error": "Failed to fetch activities"}), 500
    except Exception as e:
        logger.error(f"Error in facebook_get_activities_by_adaccount: {e}")
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