import os
import requests
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, jwk

app = FastAPI()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
OIDC_DISCOVERY_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
ALGORITHM = "RS256"

JWKS_CACHE = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_jwks():
    oidc_config = requests.get(OIDC_DISCOVERY_URL).json()
    jwks_uri = oidc_config["jwks_uri"]

    jwks = requests.get(jwks_uri).json()
    keys = jwks.get("keys", [])
    if not keys:
        raise HTTPException(status_code=500, detail="No keys found in JWKS")
    return keys


def get_jwk_for_kid(kid: str):
    if kid in JWKS_CACHE:
        return JWKS_CACHE[kid]
    keys = load_jwks()

    for key_data in keys:
        if key_data.get("kid") == kid:
            jwk_obj = jwk.construct(key_data, ALGORITHM)
            JWKS_CACHE[kid] = jwk_obj
            return jwk_obj

    raise HTTPException(status_code=401, detail=f"No matching kid '{kid}' found in JWKS")


def validate_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        token = authorization.split(" ")[1]
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="No kid in token header")
        payload = jwt.decode(token, get_jwk_for_kid(kid), algorithms=[ALGORITHM])
        roles = payload.get("realm_access", {}).get("roles", [])
        if "prothetic_user" not in roles:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authorization error")
    return payload


@app.get("/reports")
def get_reports(user=Depends(validate_token)):
    return "mock response"