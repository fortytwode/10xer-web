import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    SECRET_KEY = os.getenv("SECRET_KEY") or "fallback-secret"

class MCPConfig:
    FACEBOOK_API_VERSION = "v18.0"
    MCP_TOKEN_EXPIRY_HOURS = 24
    AUTHORIZATION_CODE_EXPIRY_MINUTES = 10
    MAX_FACEBOOK_API_RETRIES = 3
    
    # Claude connector URLs (update for production)
    AUTHORIZATION_ENDPOINT = os.getenv('AUTHORIZATION_ENDPOINT', 
                                      'https://10xer-web-production.up.railway.app/integrations/api/mcp-auth/authorize')
    TOKEN_ENDPOINT = os.getenv('TOKEN_ENDPOINT', 
                              'https://10xer-web-production.up.railway.app/mcp-api/token')
