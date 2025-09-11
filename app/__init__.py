from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import CollectionInvalid
from flask_login import LoginManager
from app.config import Config
from app.models import user

from app.models import user, token  # import token model here too

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enable CORS for API routes
    # CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Enable CORS for /api/* and /mcp-api/* endpoints with open origins
    CORS(app, resources={
        r"/api/*": {"origins": "*"},
        r"/mcp-api/*": {"origins": "*"}  # Add this line
    })

    # MongoDB setup
    mongo_client = MongoClient(app.config["MONGO_URI"])
    db = mongo_client.get_database("10Xer")

    # Create 'users' collection if not exists (no schema validation here)
    try:
        db.create_collection("users")
        print("Collection 'users' created without schema validation.")
    except CollectionInvalid:
        print("Collection 'users' already exists.")

    # Assign MongoDB users collection to User model
    user.User.collection = db["users"]

    # Create 'tokens' collection if not exists (no schema validation here)
    try:
        db.create_collection("tokens")
        print("Collection 'tokens' created without schema validation.")
    except CollectionInvalid:
        print("Collection 'tokens' already exists.")

    # Assign MongoDB tokens collection to Token model
    token.Token.collection = db["tokens"]

    # Flask-Login setup
    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return user.User.get(user_id)

    # Register Blueprints
    from app.controllers.auth_controller import auth_bp
    from app.controllers.dashboard_controller import dashboard_bp
    from app.controllers.integrations_controller import integrations_bp
    from app.controllers.mcp_api import mcp_api  # ✅ Import your SSE API here

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(integrations_bp, url_prefix="/integrations")
    app.register_blueprint(mcp_api, url_prefix="/mcp-api")  # ✅ Register your /mcp-api/sse blueprint

    @app.route("/", methods=["GET"])
    def welcome():
        return jsonify({"message": "Welcome to the MongoDB-powered API"}), 200
    

    # Add this route at the app level (not in a blueprint)
    @app.route('/.well-known/oauth-authorization-server')
    def oauth_discovery():
        return jsonify({
            "authorization_endpoint": "https://10xer-web-production.up.railway.app/integrations/api/mcp-auth/authorize",
            "token_endpoint": "https://10xer-web-production.up.railway.app/mcp-api/token"
        })
    
    @app.route('/images/<path:filename>')
    def images(filename):
        return send_from_directory('images', filename)

    return app

