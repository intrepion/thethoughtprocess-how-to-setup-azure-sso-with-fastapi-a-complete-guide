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


# --- Authentication Logic ---
# (We don't need manual token verification with sessions, but this can be useful for other purposes)


# --- Dependencies ---
def require_auth(request: Request):
    """
    Dependency to protect an endpoint.
    Raises an exception if the user is not authenticated.
    """
    user = request.session.get("user")
    if not user:
        response = RedirectResponse(url="/login", status_code=302)
        raise HTTPException(status_code=response.status_code, headers=response.headers)
    return user


def require_roles(required_roles: List[str]):
    """
    Dependency factory to check for required roles in the session.
    """

    def role_checker(user: Dict[str, Any] = Depends(require_auth)):
        user_roles = user.get("roles", [])
        if not any(role in user_roles for role in required_roles):
            response = RedirectResponse(url="/login", status_code=302)
            raise HTTPException(
                status_code=response.status_code, headers=response.headers
            )
        return user

    return role_checker


@app.get("/protected")
async def protected_endpoint(user=Depends(require_auth)):
    """
    A protected endpoint that requires authentication via session.
    """

    return {
        "message": f"Hello, {user.get('name')}! This is protected data.",
        "user_details": user,
    }


@app.get("/roleProtected", dependencies=[Depends(require_roles(["Admin"]))])
async def role_protected_endpoint(user=Depends(require_auth)):
    """
    An endpoint protected by role 'Admin'.
    """

    return {
        "message": f"Welcome, Admin {user.get('name')}!",
        "detail": "You have access to this role-protected data.",
    }


@app.get("/unprotected")
async def unprotected_endpoint():
    """
    An unprotected endpoint that anyone can access.
    """
    return {"message": "This is an unprotected endpoint."}


if __name__ == "__main__":
    import uvicorn

    # This is for development only. In production, use a proper ASGI server.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
