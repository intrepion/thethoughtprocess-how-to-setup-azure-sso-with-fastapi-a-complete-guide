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

# --- API Endpoints ---


@app.get("/login")
async def login(request: Request):
    """
    Initiate the Microsoft Entra ID login flow.
    Stores the state in the session.
    """
    state = secrets.token_urlsafe(32)
    request.session["state"] = state

    authorization_url = msal_client.get_authorization_request_url(
        scopes=SCOPE, state=state, redirect_uri=AZURE_REDIRECT_URI
    )
    return RedirectResponse(url=authorization_url)


@app.get("/login/callback")
async def callback(code: str, state: str, request: Request):
    """
    Handle the OAuth callback from Microsoft Entra ID.
    Stores the user's token and info in the session.
    """
    # Verify the state to prevent CSRF attacks
    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    request.session.pop("state", None)

    token_response = msal_client.acquire_token_by_authorization_code(
        code=code, scopes=SCOPE, redirect_uri=AZURE_REDIRECT_URI
    )

    if "error" in token_response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=token_response.get("error_description", "Failed to acquire token"),
        )

    # The id_token contains user claims
    id_token_claims = jwt.decode(
        token_response["id_token"],
        options={
            "verify_signature": False
        },  # Signature already verified by MSAL/Entra ID
    )

    # Store user information in the session
    request.session["user"] = {
        "id": id_token_claims.get("oid"),
        "name": id_token_claims.get("name"),
        "email": id_token_claims.get("preferred_username"),
        "roles": id_token_claims.get("roles", []),
    }

    return RedirectResponse(url="/protected")
