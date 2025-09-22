from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models.user import User
from app.utils.email_utils import send_verification_email
import uuid
from flask import session
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
import os

auth_bp = Blueprint("auth", __name__)


GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', 'your-client-id-here')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', 'your-client-secret-here')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:7777/callback')  # Change in production

GOOGLE_REDIRECT_LOGIN_SUCCESS = os.getenv('GOOGLE_REDIRECT_LOGIN_SUCCESS', 'http://localhost:7777/home')

# @auth_bp.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         email = request.form["email"]
#         user = User.get_by_email(email)

#         if not user:
#             # New user registration
#             user = User.create(email)
#             is_email_verified = False
#         else:
#             is_email_verified = user.user_dict.get("isEmailVerify", False)

#         if not is_email_verified:
#             token = str(uuid.uuid4())
#             User.save_email_token(email, token)
#             send_verification_email(email, token)
#             return redirect(url_for("auth.verify_request", provider="email", type="email"))

#         # ✅ Log the user in so current_user will work
#         login_user(user)

#         return redirect(url_for("dashboard.dashboard"))

#     return render_template("login.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    print("Debug: Entered login route")  # Debug line
    
    if request.method == "POST":
        email = request.form["email"]
        print(f"Debug: POST login attempt with email: {email}")  # Debug line
        
        user = User.get_by_email(email)
        print(f"Debug: User lookup result: {user}")  # Debug line
        
        if not user:
            print("Debug: No user found, creating new user")  # Debug line
            # New user registration
            user = User.create(email)
            is_email_verified = False
        else:
            is_email_verified = user.user_dict.get("isEmailVerify", False)
            print(f"Debug: User email verification status: {is_email_verified}")  # Debug line

        if not is_email_verified:
            token = str(uuid.uuid4())
            print(f"Debug: Email not verified, generated token: {token}")  # Debug line
            User.save_email_token(email, token)
            send_verification_email(email, token)
            return redirect(url_for("auth.verify_request", provider="email", type="email"))

        # Log the user in so current_user will work
        login_user(user)
        print(f"Debug: User logged in: {user}")  # Debug line

        # Check if this is part of MCP flow
        mcp_redirect = request.args.get('mcp_redirect')
        mcp_state = request.args.get('mcp_state') 
        mcp_client = request.args.get('mcp_client')
        print(f"Debug: MCP params - redirect: {mcp_redirect}, state: {mcp_state}, client: {mcp_client}")  # Debug line
        
        if mcp_redirect and mcp_state:
            # This is MCP flow - save params and start Facebook OAuth
            session.update({
                'mcp_redirect_uri': mcp_redirect,
                'mcp_state': mcp_state,
                'mcp_client_id': mcp_client
            })
            print("Debug: Starting Facebook OAuth flow")  # Debug line
            
            fb_state = str(uuid.uuid4())
            session['fb_oauth_state'] = fb_state
            print(f"Debug: Generated fb_oauth_state: {fb_state}")  # Debug line
            
            fb_auth_url = (
                f"https://www.facebook.com/v23.0/dialog/oauth?"
                f"client_id={os.getenv('FACEBOOK_APP_ID')}&"
                f"redirect_uri={os.getenv('FACEBOOK_REDIRECT_URI')}&"
                f"scope=ads_read,ads_management,business_management,pages_read_engagement,pages_manage_ads&"
                f"response_type=code&"
                f"state={fb_state}"
            )
            print(f"Debug: Redirecting to Facebook OAuth URL: {fb_auth_url}")  # Debug line
            return redirect(fb_auth_url)

        # Regular login flow
        print("Debug: Redirecting to dashboard")  # Debug line
        return redirect(url_for("dashboard.dashboard"))

    # GET request - check for MCP params and preserve them
    mcp_redirect = request.args.get('mcp_redirect')
    mcp_state = request.args.get('mcp_state')
    mcp_client = request.args.get('mcp_client')
    print(f"Debug: GET request - MCP params: redirect={mcp_redirect}, state={mcp_state}, client={mcp_client}")  # Debug line
    
    return render_template("login.html", 
                         mcp_redirect=mcp_redirect, 
                         mcp_state=mcp_state, 
                         mcp_client=mcp_client)

@auth_bp.route("/users/verify-request")
def verify_request():
    provider = request.args.get("provider")
    type_ = request.args.get("type")
    return render_template("userVerify.html")

@auth_bp.route("/users/api/auth/callback/email")
def verify_email_token():
    token = request.args.get("token")
    email = request.args.get("email")
    user = User.get_by_email_token(email, token)

    if user:
        login_user(user)
        user.clear_email_token()
        user.verify_email(user.email)
        return redirect(url_for("dashboard.dashboard"))  # or wherever
    else:
        flash("Invalid or expired link", "danger")
        return redirect(url_for("auth.login"))
    
from flask import redirect, make_response, session

@auth_bp.route("/logout")
@login_required
def logout():
    print("Logout route called")
    
    logout_user()
    print(f"User logged out. current_user.is_authenticated: {current_user.is_authenticated}")
    
    print(f"Session before clear: {dict(session)}")
    session.clear()  # Optional: clear all session keys
    print("Session cleared")
    
    resp = make_response(redirect("/"))
    print("Redirect response created")
    
    resp.set_cookie('session', '', expires=0)  # Remove session cookie
    print("Session cookie expired")
    
    return resp


@auth_bp.route("/login/google")
def google_login():
    google_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }

    from urllib.parse import urlencode
    url = f"{google_auth_endpoint}?{urlencode(params)}"
    return redirect(url)

@auth_bp.route("/api/auth/google", methods=['POST', 'GET'])
def google_callback():
    code = request.args.get("code")
    print("Code received:", code)
    if not code:
        print("No code provided, returning error")
        return "No authorization code provided", 400

    try:
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        print("Sending POST to token URL with data:", data)

        token_resp = requests.post(token_url, data=data)
        print("Token response status:", token_resp.status_code)
        token_json = token_resp.json()
        print("Token response JSON:", token_json)

        access_token = token_json.get("access_token")
        id_token_val = token_json.get("id_token")

        if not access_token or not id_token_val:
            print("Missing access_token or id_token in response")
            return "Token error: Missing access_token or id_token", 400

        print("Verifying ID token")
        id_info = id_token.verify_oauth2_token(
            id_token_val,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = id_info.get("email")
        print("Email from ID token:", email)
        if not email:
            print("Email not found in ID token")
            return "Email not found in ID token", 400

        user = User.get_by_email(email)
        print("User fetched from DB:", user)
        if not user:
            print("User not found, creating new user")
            user = User.create(email)

        print("Updating email verification status")
        User.verify_email(email)
        user.user_dict["isEmailVerify"] = True

        print("Logging in user:", user.email)
        login_user(user)

        session['user_email'] = email
        session['user_picture'] = id_info.get("picture")

        print("Redirecting to success page")
        return redirect(GOOGLE_REDIRECT_LOGIN_SUCCESS)

    except Exception as e:
        print("Login failed with exception:", str(e))
        return f"Login failed: {str(e)}", 500
    
@auth_bp.route("/claude/mcp-auth/authorize", methods=["GET"])
def mcp_authorize():
    print("Debug: Entered mcp_authorize route")  # Debug line
    
    # Check 10Xer login
    if session.get("user"):
        print("Debug: User is logged in, redirecting to integrations")  # Debug line
        return redirect("https://10xer-web-production.up.railway.app/integrations/integrations")
    
    # Not logged in → redirect to login
    login_url = "https://10xer-web-production.up.railway.app/login"
    next_url = "https://10xer-web-production.up.railway.app/integrations/integrations"
    print(f"Debug: User not logged in, redirecting to login page with next={next_url}")  # Debug line
    return redirect(f"{login_url}?next={next_url}")

# @auth_bp.route("/claude/mcp-auth/authorize", methods=["GET"])
# def mcp_authorize():
#     # Grab 'state' param from Claude
#     state = request.args.get("state")
    
#     if session.get("user"):
#         FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
#         redirect_uri = "https://claude.ai/mcp-api/oauth/callback"

#         fb_oauth_url = (
#             "https://www.facebook.com/v16.0/dialog/oauth?"
#             f"client_id={FACEBOOK_APP_ID}"
#             "&response_type=code"
#             f"&redirect_uri={redirect_uri}"
#             "&scope=ads_read,ads_management,business_management"
#         )

#         # Append state param if present (must pass through exactly)
#         if state:
#             fb_oauth_url += f"&state={state}"

#         return redirect(fb_oauth_url)

#     else:
#         # Not logged in → redirect to login with next param
#         login_url = "https://10xer-web-production.up.railway.app/login"
#         # Also forward state param here so that after login you can redirect back properly
#         next_url = "https://10xer-web-production.up.railway.app/claude/mcp-auth/authorize"
#         if state:
#             next_url += f"?state={state}"
#         return redirect(f"{login_url}?next={next_url}")

# @auth_bp.route("/claude/mcp-auth/authorize", methods=["GET"])
# def mcp_authorize():
#     FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
#     redirect_uri = "https://claude.ai/mcp-api/oauth/callback"  # Must match FB app redirect URI
#     fb_oauth_url = (
#         "https://www.facebook.com/v16.0/dialog/oauth?"
#         f"client_id={FACEBOOK_APP_ID}"
#         "&response_type=code"
#         f"&redirect_uri={redirect_uri}"
#         "&scope=ads_read,ads_management,business_management"
#     )
#     return redirect(fb_oauth_url)
    
# @auth_bp.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         email = request.form["email"]
#         user = User.get_by_email(email)
#         if not user:
#             user = User.create(email)
#         login_user(user)
#         return redirect(url_for("integrations.integrations"))  # <-- use redirect here
#     return render_template("login.html")

# @auth_bp.route("/logout")
# @login_required
# def logout():
#     logout_user()
#     return redirect("/")
