from flask import jsonify
from werkzeug.http import HTTP_STATUS_CODES
from app.api import bp


def error_response(status_code, message=None):
    """
    Build a JSON error response with the given status_code.
    Optionally, attach a more detailed message.
    """
    payload = {
        'error': HTTP_STATUS_CODES.get(status_code, 'Unknown Error')
    }
    if message:
        payload['message'] = message
    response = jsonify(payload)
    response.status_code = status_code
    return response


def bad_request(message):
    """
    Helper for common case: status code 400 Bad Request.
    """
    return error_response(400, message)


@bp.app_errorhandler(404)
def not_found_error(e):
    """
    Return JSON 404 response if an endpoint isn't found within /api/.
    """
    return error_response(404, "Resource not found.")


@bp.app_errorhandler(500)
def internal_error(e):
    """
    Return JSON 500 response if a server error occurs within /api/.
    """
    return error_response(500, "Internal server error.")