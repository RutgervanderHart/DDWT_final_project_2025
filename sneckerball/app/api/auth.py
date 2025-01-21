from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import sqlalchemy as sa
from app import db
from app.models import User
from app.api.errors import error_response

# Basic Auth is used for exchanging username/password for a token
basic_auth = HTTPBasicAuth()

@basic_auth.verify_password
def verify_password(username, password):
    """
    Verify user credentials for BasicAuth.
    Returns the user object if valid, or None if invalid.
    """
    user = db.session.scalar(sa.select(User).where(User.username == username, User.is_deleted == False))
    if user and user.check_password(password):
        return user
    return None

@basic_auth.error_handler
def basic_auth_error(status):
    """
    Returns a JSON error when Basic Auth fails (usually 401).
    """
    return error_response(status)


# Token Auth is used for all subsequent protected requests
token_auth = HTTPTokenAuth(scheme='Bearer')

@token_auth.verify_token
def verify_token(token):
    """
    Returns the user if token is valid, else None.
    """
    user = User.check_token(token)
    if not user or user.is_deleted:
        return None
    return user

@token_auth.error_handler
def token_auth_error(status):
    """
    Returns a JSON error when Token Auth fails (usually 401).
    """
    return error_response(status)
