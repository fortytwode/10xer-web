from flask import Blueprint, render_template, redirect
from flask_login import login_required, current_user
from app.models.user import User
from app.models.token import Token

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    user = User.get(current_user.id)

    # Fetch Facebook token (or other integration token)
    token_obj = Token.get_by_user_id_and_type(current_user.id, "facebook")
    access_token = token_obj.token if token_obj else None

    return render_template(
        "dashboard.html",
        email=user.email,
        api_key=user.user_dict.get("api_key"),  # your existing API key
        access_token=access_token               # pass the access token here
    )

@dashboard_bp.route("/generate-api-key", methods=["POST"])
@login_required
def generate_api_key_route():
    user = User.get(current_user.id)
    if user.api_key:
        # API key already exists, just redirect
        return redirect("/dashboard")

    User.generate_api_key(user.id)
    # Re-fetch user to get new api_key if needed
    user = User.get(current_user.id)
    return redirect("/dashboard")
