from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
print("SENDGRID_API_KEY:", SENDGRID_API_KEY)
LIVE_APP_URL = os.getenv("LIVE_APP_URL")

def send_verification_email(to_email, token):
    verify_url = f"{LIVE_APP_URL}/users/api/auth/callback/email?token={token}&email={to_email}"
    
    html_content = f"""
    <p>Click the button below to securely sign in to your 10xer account.</p>
    <a href="{verify_url}" style="padding: 10px 20px; background-color: #009688; color: white; text-decoration: none; border-radius: 5px;">Sign in to 10xer</a>
    <p>This link will expire in 24 hours for your security.</p>
    """

    message = Mail(
        from_email="mahmadimran1110@gmail.com",  # ✅ Make sure this is verified in SendGrid
        to_emails=to_email,
        subject='Sign in to your 10xer account',
        html_content=html_content
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Email sent to {to_email}. Status code: {response.status_code}")
    except Exception as e:
        print(f"SendGrid error: {e}")
