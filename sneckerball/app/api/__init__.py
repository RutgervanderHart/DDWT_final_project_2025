from flask import Blueprint

bp = Blueprint('api', __name__)

# Import the modules that define the routes and supporting code
from app.api import auth, errors, users, snackbars, reviews