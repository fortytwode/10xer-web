import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")  # e.g., yourname@gmail.com
GMAIL_PASS = os.getenv("GMAIL_PASS")  # App password (not your main password)
LIVE_APP_URL = os.getenv("LIVE_APP_URL")

def send_verification_email(to_email, token):
    verify_url = f"{LIVE_APP_URL}/users/api/auth/callback/email?token={token}&email={to_email}"
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Sign in to your 10xer account"
    msg["From"] = GMAIL_USER
    msg["To"] = to_email

    html_content = f"""
    <html>
    <body>
        <p>Click the button below to securely sign in to your 10xer account.</p>
        <a href="{verify_url}" style="padding: 10px 20px; background-color: #009688; color: white; text-decoration: none; border-radius: 5px;">Sign in to 10xer</a>
        <p>This link will expire in 24 hours for your security.</p>
    </body>
    </html>
    """

    part = MIMEText(html_content, "html")
    msg.attach(part)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_PASS)
            server.sendmail(GMAIL_USER, to_email, msg.as_string())
            print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Gmail SMTP error: {e}")