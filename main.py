import httpx
import secrets
import os
from jose import jwt, JWTError
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import msal
from starlette.middleware.session import SessionMiddleware

AZURE_CLIENT_ID = f""  # Retrieved from previous step
AZURE_CLIENT_SECRET = f""  # Retrieved from previous step
AZURE_TENANT_ID = f""  # Retrieved from previous step
AZURE_REDIRECT_URI = f""  # The redirect URL you defined in the app registration
SECRET_KEY = f""  # Random value you choose for securing the session
AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
SCOPE = ["User.Read"]  # This scope will be used to say ( we want to access user info)

app = FastAPI()

# Add session middleware
# NOTE: In production, ensure 'https_only=True' and 'samesite="none"' for cross-site SSO redirects.
app.add_middleware(
    SessionMiddleware, secret_key=SECRET_KEY, https_only=True, samesite="none"
)

# Initialize MSAL Confidential Client
msal_client = msal.ConfidentialClientApplication(
    client_id=AZURE_CLIENT_ID,
    authority=AUTHORITY,
    client_credential=AZURE_CLIENT_SECRET,
)
