from flask import (Blueprint, redirect, url_for, session, request)
from flask.wrappers import Request
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route("/test", methods=("GET",))
def test():
    return "Hello World"

@bp.route("/adduser", methods=("POST",))
def add_user():
    print(request.json)
    return "200"
