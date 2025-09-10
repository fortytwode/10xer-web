from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models.user import User
from app.utils.email_utils import send_verification_email
import uuid

auth_bp = Blueprint("auth", __name__)

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
