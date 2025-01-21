from flask import request, url_for, jsonify, abort
import sqlalchemy as sa
from app import db
from app.models import User
from app.api import bp
from app.api.auth import token_auth, basic_auth
from app.api.errors import bad_request

@bp.route('/tokens', methods=['POST'])
@basic_auth.login_required
def get_token():
    """
    POST /api/tokens
    Obtain a token by providing Basic Auth (username & password).
    """
    user = basic_auth.current_user()
    token = user.get_token()
    return jsonify({'token': token})

@bp.route('/tokens', methods=['DELETE'])
@token_auth.login_required
def revoke_token():
    """
    DELETE /api/tokens
    Revoke (invalidate) the current token.
    """
    user = token_auth.current_user()
    user.revoke_token()
    return '', 204


@bp.route('/users', methods=['POST'])
def create_user():
    """
    POST /api/users
    Create a new user account (no auth required).
    Expected JSON fields: username, email, password
    Optional: about_me
    """
    data = request.get_json() or {}
    # Basic validation
    if 'username' not in data or 'email' not in data or 'password' not in data:
        return bad_request("Must include username, email, and password fields.")

    # Check uniqueness
    if db.session.scalar(sa.select(User).where(User.username == data['username'], User.is_deleted == False)):
        return bad_request("Please use a different username.")
    if db.session.scalar(sa.select(User).where(User.email == data['email'], User.is_deleted == False)):
        return bad_request("Please use a different email address.")

    user = User()
    user.from_dict(data, new_user=True)
    db.session.add(user)
    db.session.commit()

    # Return 201 + newly created resource
    response = jsonify(user.to_dict(include_email=True))
    response.status_code = 201
    response.headers['Location'] = url_for('api.get_user', id=user.id)
    return response

@bp.route('/users', methods=['GET'])
@token_auth.login_required
def get_users():
    """
    GET /api/users
    Returns a list of users (JSON array).
    Access requires a valid token.
    """
    users = db.session.scalars(sa.select(User).where(User.is_deleted == False)).all()
    return jsonify([u.to_dict() for u in users])

@bp.route('/users/<int:id>', methods=['GET'])
@token_auth.login_required
def get_user(id):
    """
    GET /api/users/<id>
    Returns a single user by ID.
    Only the user slef or an admin sees the email in the response.
    """
    user = db.get_or_404(User, id)
    if user.is_deleted:
        abort(404)  # Deleted user acts as "not found"

    # If the current user is the same or is admin, show email
    include_email = (token_auth.current_user().id == user.id) or token_auth.current_user().is_admin
    return jsonify(user.to_dict(include_email=include_email))

@bp.route('/users/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_user(id):
    """
    PUT /api/users/<id>
    Updates user data. Only allowed if current user matches ID or is admin.
    """
    user = db.get_or_404(User, id)
    if user.is_deleted:
        abort(404)

    current_user = token_auth.current_user()
    # Only allow self-updates or admin
    if (current_user.id != user.id) and (not current_user.is_admin):
        abort(403)

    data = request.get_json() or {}

    # Check if new username or email is unique
    if 'username' in data and data['username'] != user.username:
        if db.session.scalar(sa.select(User).where(User.username == data['username'], User.is_deleted == False)):
            return bad_request("Please use a different username.")
    if 'email' in data and data['email'] != user.email:
        if db.session.scalar(sa.select(User).where(User.email == data['email'], User.is_deleted == False)):
            return bad_request("Please use a different email address.")

    user.from_dict(data, new_user=False)
    db.session.commit()
    return jsonify(user.to_dict(include_email=(current_user.id == user.id or current_user.is_admin)))

@bp.route('/users/<int:id>', methods=['DELETE'])
@token_auth.login_required
def delete_user(id):
    """
    DELETE /api/users/<id>
    Soft-delete the user if you are the user or an admin.
    This will also soft-delete any snackbars/reviews they own.
    """
    user = db.get_or_404(User, id)
    if user.is_deleted:
        abort(404)

    current_user = token_auth.current_user()
    if (current_user.id != user.id) and (not current_user.is_admin):
        abort(403)

    user.soft_delete()
    db.session.commit()
    return '', 204
