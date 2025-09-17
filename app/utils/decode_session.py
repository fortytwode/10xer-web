from flask.sessions import SecureCookieSessionInterface

def decode_flask_session(session_cookie_value, app):
    class DummySessionInterface(SecureCookieSessionInterface):
        def get_signing_serializer(self, app):
            return super().get_signing_serializer(app)

    serializer = DummySessionInterface().get_signing_serializer(app)
    if not serializer:
        return {}

    try:
        data = serializer.loads(session_cookie_value)
        return data  # session dict
    except Exception as e:
        print("Session decoding error:", str(e))
        return {}