from flask import Blueprint, request, jsonify, Response, stream_with_context
from app.models.user import User
from app.models.token import Token
# import uuid
# import time

mcp_api = Blueprint("mcp_api", __name__)

@mcp_api.route("/facebook_token", methods=["GET"])
def get_facebook_token():
    auth_header = request.headers.get("Authorization")
    print(f"AUTH HEADER RECEIVED: {auth_header}")
    
    if not auth_header:
        return jsonify({
            "success": False,
            "message": "Missing 'Authorization' header."
        }), 401

    parts = auth_header.split()
    print(f"Header parts: {parts}")
    
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({
            "success": False,
            "message": "Invalid Authorization header format. Expected 'Bearer <API_KEY>'"
        }), 401
    
    api_key = parts[1]
    print(f"API Key extracted: {api_key}")
    
    user = User.get_by_api_key(api_key)
    print(f"User fetched: {user}")
    
    if not user:
        return jsonify({
            "success": False,
            "message": "Invalid or expired API key."
        }), 403

    token_obj = Token.get_by_user_id_and_type(user.id, "facebook")
    print(f"Token object fetched: {token_obj}")

    # Debug individual fields of the token object if it's not None
    if token_obj:
        print(f"Token ID: {token_obj.id}")
        print(f"User ID: {token_obj.user_id}")
        print(f"Token Type: {token_obj.token_type}")
        print(f"Access Token: {token_obj.token}")   
    else:
        print("No token object found.")

    if not token_obj:
        return jsonify({
            "success": False,
            "message": "Facebook token not found for user."
        }), 404

    return jsonify({
        "success": True,
        "facebook_access_token": token_obj.token
    }), 200

# @mcp_api.route("/sse", methods=["GET"])
# def sse_stream():
#     auth_header = request.headers.get("Authorization")
#     print(f"AUTH HEADER RECEIVED: {auth_header}")
    
#     if not auth_header:
#         return jsonify({
#             "success": False,
#             "message": "Missing 'Authorization' header."
#         }), 401

#     parts = auth_header.split()
#     if len(parts) != 2 or parts[0].lower() != "bearer":
#         return jsonify({
#             "success": False,
#             "message": "Invalid Authorization header format. Expected 'Bearer <API_KEY>'"
#         }), 401
    
#     api_key = parts[1]
#     user = User.get_by_api_key(api_key)
#     if not user:
#         return jsonify({
#             "success": False,
#             "message": "Invalid or expired API key."
#         }), 403
    
#     session_id = str(uuid.uuid4())  # generate a new unique session id per connection

#     def event_stream():
#         # Send initial authentication confirmation message
#         # initial_data = {
#         #     "jsonrpc": "2.0",
#         #     "method": "authConfirmation",
#         #     "params": {
#         #         "success": True,
#         #         "message": f"Authentication successful for user: {user.email}",
#         #         "email": user.email,
#         #         "user_id": user.get_id()
#         #     },  
#         #     "id": 1
#         # }
#         # yield f"data: {json.dumps(initial_data)}\n\n"
#         message = f"/mcp-api/messages?sessionId={session_id}"
#         yield f"data: {message}\n\n"

#         # Heartbeat every 15 seconds
#         while True:
#             message = f"/mcp-api/messages?sessionId={session_id}"
#             yield f"data: {message}\n\n"
#             time.sleep(15)

#     return Response(stream_with_context(event_stream()), mimetype='text/event-stream')