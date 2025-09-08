from app import create_app
import os

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 7777))
    # Disable debug mode in production
    debug_mode = os.environ.get('FLASK_ENV', 'development') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)