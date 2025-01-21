from flask import request, jsonify, abort
import sqlalchemy as sa
from app import db
from app.models import Snackbar
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request

@bp.route('/snackbars', methods=['GET'])
@token_auth.login_required
def get_snackbars():
    """
    GET /api/snackbars
    Returns a list of available snackbars (not soft-deleted).
    """
    sb_list = db.session.scalars(
        sa.select(Snackbar).where(Snackbar.is_deleted == False)
    ).all()
    return jsonify([sb.to_dict() for sb in sb_list])

@bp.route('/snackbars/<int:id>', methods=['GET'])
@token_auth.login_required
def get_snackbar(id):
    """
    GET /api/snackbars/<id>
    Returns a single snackbar by ID.
    """
    snackbar = db.get_or_404(Snackbar, id)
    if snackbar.is_deleted:
        abort(404)
    return jsonify(snackbar.to_dict())

@bp.route('/snackbars', methods=['POST'])
@token_auth.login_required
def create_snackbar():
    """
    POST /api/snackbars
    Create a new snackbar. The authenticated user becomes the owner.
    Required JSON fields: name
    Optional fields: about
    """
    current_user = token_auth.current_user()
    data = request.get_json() or {}

    if 'name' not in data:
        return bad_request("Must include a 'name' for the snackbar.")

    # Ensure name uniqueness
    existing = db.session.scalar(sa.select(Snackbar).where(Snackbar.name == data['name'], Snackbar.is_deleted == False))
    if existing:
        return bad_request("Please use a different name, as that name is already in use.")

    snackbar = Snackbar(owner=current_user)
    snackbar.from_dict(data)
    db.session.add(snackbar)
    db.session.commit()

    return jsonify(snackbar.to_dict()), 201

@bp.route('/snackbars/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_snackbar(id):
    """
    PUT /api/snackbars/<id>
    Update an existing snackbar's fields (owner only or admin).
    """
    snackbar = db.get_or_404(Snackbar, id)
    if snackbar.is_deleted:
        abort(404)

    current_user = token_auth.current_user()
    if (current_user.id != snackbar.owner.id) and (not current_user.is_admin):
        abort(403)  # Forbidden

    data = request.get_json() or {}
    if 'name' in data and data['name'] != snackbar.name:
        # Check uniqueness
        existing = db.session.scalar(sa.select(Snackbar).where(Snackbar.name == data['name'], Snackbar.is_deleted == False))
        if existing:
            return bad_request("A snackbar with that name already exists.")

    snackbar.from_dict(data)
    db.session.commit()
    return jsonify(snackbar.to_dict())

@bp.route('/snackbars/<int:id>', methods=['DELETE'])
@token_auth.login_required
def delete_snackbar(id):
    """
    DELETE /api/snackbars/<id>
    Soft-delete an existing snackbar (owner or admin).
    """
    snackbar = db.get_or_404(Snackbar, id)
    if snackbar.is_deleted:
        abort(404)

    current_user = token_auth.current_user()
    if (current_user.id != snackbar.owner.id) and (not current_user.is_admin):
        abort(403)

    snackbar.soft_delete()
    db.session.commit()
    return '', 204
