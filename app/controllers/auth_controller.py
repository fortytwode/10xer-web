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

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        user = User.get_by_email(email)

        if not user:
            # New user registration
            user = User.create(email)
            is_email_verified = False
        else:
            is_email_verified = user.user_dict.get("isEmailVerify", False)

        if not is_email_verified:
            token = str(uuid.uuid4())
            User.save_email_token(email, token)
            send_verification_email(email, token)
            return redirect(url_for("auth.verify_request", provider="email", type="email"))

        # ✅ Log the user in so current_user will work
        login_user(user)

        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html")

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
    
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

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
