from flask import request, jsonify, abort
import sqlalchemy as sa
from app import db
from app.models import Review, Snackbar, User
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request

@bp.route('/reviews/<int:id>', methods=['GET'])
@token_auth.login_required
def get_review(id):
    """
    GET /api/reviews/<id>
    Return a single review by ID.
    """
    review = db.get_or_404(Review, id)
    if review.is_deleted:
        abort(404)
    return jsonify(review.to_dict())

@bp.route('/snackbars/<int:snackbar_id>/reviews', methods=['GET'])
@token_auth.login_required
def get_snackbar_reviews(snackbar_id):
    """
    GET /api/snackbars/<snackbar_id>/reviews
    Return all reviews for a given snackbar.
    """
    snackbar = db.get_or_404(Snackbar, snackbar_id)
    if snackbar.is_deleted:
        abort(404)
    reviews = db.session.scalars(
        sa.select(Review).where(Review.snackbar_id == snackbar_id, Review.is_deleted == False)
    ).all()
    return jsonify([r.to_dict() for r in reviews])

@bp.route('/users/<int:user_id>/reviews', methods=['GET'])
@token_auth.login_required
def get_user_reviews(user_id):
    """
    GET /api/users/<user_id>/reviews
    Return all reviews authored by a specific user.
    """
    user = db.get_or_404(User, user_id)
    if user.is_deleted:
        abort(404)
    reviews = db.session.scalars(
        sa.select(Review).where(Review.user_id == user_id, Review.is_deleted == False)
    ).all()
    return jsonify([r.to_dict() for r in reviews])

@bp.route('/snackbars/<int:snackbar_id>/reviews', methods=['POST'])
@token_auth.login_required
def create_review(snackbar_id):
    """
    POST /api/snackbars/<snackbar_id>/reviews
    Create a new review for a given snackbar.
    Required fields: body
    """
    snackbar = db.get_or_404(Snackbar, snackbar_id)
    if snackbar.is_deleted:
        abort(404)

    data = request.get_json() or {}
    if 'body' not in data:
        return bad_request("Review must have a 'body' field.")

    review = Review(author=token_auth.current_user(), subject=snackbar)
    review.from_dict(data)
    db.session.add(review)
    db.session.commit()
    return jsonify(review.to_dict()), 201

@bp.route('/reviews/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_review(id):
    """
    PUT /api/reviews/<id>
    Update existing review text. Only allowed if user is the review's author or is admin.
    """
    review = db.get_or_404(Review, id)
    if review.is_deleted:
        abort(404)

    current_user = token_auth.current_user()
    if (current_user.id != review.user_id) and (not current_user.is_admin):
        abort(403)

    data = request.get_json() or {}
    review.from_dict(data)
    db.session.commit()
    return jsonify(review.to_dict())

@bp.route('/reviews/<int:id>', methods=['DELETE'])
@token_auth.login_required
def delete_review(id):
    """
    DELETE /api/reviews/<id>
    Soft-delete an existing review. Author or admin can delete.
    """
    review = db.get_or_404(Review, id)
    if review.is_deleted:
        abort(404)

    current_user = token_auth.current_user()
    if (current_user.id != review.user_id) and (not current_user.is_admin):
        abort(403)

    review.soft_delete()
    db.session.commit()
    return '', 204
