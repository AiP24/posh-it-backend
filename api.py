from flask import (Blueprint, redirect, url_for, session, request, current_app)
from flask.cli import with_appcontext
from flask.wrappers import Request, Response
from functools import wraps
import flask_bcrypt
# import flask_jwt
import jwt
import json

from werkzeug.datastructures import ResponseCacheControl
import db
import hashlib
import uuid
import time

#setup bcrypt and jwt
# def jwt_authenticate(username, password):
#     dbo = db.get_db()
#     table = dbo.cursor()
#     output = table.execute('SELECT username FROM user WHERE username=?', (user_name,)).fetchall()
#     if len(output) <= 0:
#         return "User does not exist"

bp = Blueprint('api', __name__, url_prefix='/api')

#dev routes
@bp.route("/test", methods=("GET",))
def test():
    return "Hello World"

#auth routes
def requires_auth(func):
    @wraps(func)
    def req_auth_wrapper(*args, **kwargs):
        token_e = request.headers.get('token', None)
        if token_e:
            try:
                token = jwt.decode(token_e, current_app.config['SECRET_KEY'], algorithms="HS256")
            except Exception as exc:
                return Response(f"{{'error': '{type(exc).__name__}: {exc}'}}")
            if time.time() * 1000 > token['exp']:
                return Response("{'error': 'token expired'}", 401)
            
            dbo = db.get_db()
            table = dbo.cursor()
            user_password = table.execute("SELECT password FROM user WHERE id=?", (token['sub'],)).fetchone()

            if not current_app.bcrypt.check_password_hash(user_password['password'].encode('utf8'), token['pwdsha']):
                return Response("'error': 'invalid token'}", 401)
            
            return func(*args, **kwargs)
            
        else:
            return Response("token not supplied", 403)
    return req_auth_wrapper
        


@bp.route('/adduser', methods=['POST'])
def add_user():
    #adds user to database
    #note that you need to manually sign in afterwards
    print(request.is_json)
    if not request.is_json:
        return Response("{'error': 'input must be json', 'note': 'did you forget to set the content-type header?'}", 400, mimetype='application/json')
    data = request.json
    new_user_name = data['username'].lower() #case sensitivity is bad. Might remove later
    new_user_password = data['password']

    #first, check if user is already taken
    dbo = db.get_db()
    table = dbo.cursor()
    output = table.execute('SELECT username FROM user WHERE username=?', (new_user_name,)).fetchall()
    if len(output) > 0:
        return "User Already Taken"

    #generate important password hash
    #first get password as sha256, allowing for long passowords
    sha256_pwd = hashlib.sha256(new_user_password.encode('utf-8'))
    bcrypt_user_pwd = current_app.bcrypt.generate_password_hash(sha256_pwd.hexdigest()).decode('utf8')
    print(bcrypt_user_pwd)

    #generate a uuid
    user_id = 'd11c0ea2-5e9e-440a-aaff-fe3e9dcff118'#str(uuid.uuid4())
    while len(table.execute('SELECT id FROM user WHERE id=?', (user_id,)).fetchall()) > 0:
        #reroll duplicate uuids (if they somehow appear)
        user_id = str(uuid.uuid4())
    table.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (user_id, new_user_name, bcrypt_user_pwd))

    table.close()
    dbo.commit()
    return 'Ok'

@bp.route('/signin', methods=['POST'])
def sign_in():
    print(request.is_json)
    if not request.is_json:
        return Response("{'error': 'input must be json'}", 400, mimetype='application/json')
    data = request.json
    user_name = data['username'].lower() #case sensitivity is bad. Might remove later
    user_password = data['password']

    dbo = db.get_db()
    table = dbo.cursor()
    user = table.execute('SELECT * FROM user WHERE username=?', (user_name,)).fetchone()
    if user is None:
        return Response("User does not exist", 404)

    hashed_storage_password = user['password']#table.execute("SELECT password FROM user WHERE username=?", (user_name,)).fetchone()['password']
    hashed_input_password = hashlib.sha256(user_password.encode('utf-8')).hexdigest()
    # print(hashed_storage_password, hashed_input_password)
    if not current_app.bcrypt.check_password_hash(hashed_storage_password.encode('utf8'), hashed_input_password):
        return Response("Password is incorrect", 401)
    token_data = {
        'sub': user['id'],
        'exp': (time.time() * 1000) + (30 * 24 * 60 * 60 * 1000), #days * hr/day * min/hr * sec/min * ms/sec
        'iat': time.time() * 1000,
        'pwdsha': hashed_input_password,
    } #I hope this is safe
    encrypted_token = jwt.encode(token_data, current_app.config['SECRET_KEY'], algorithm="HS256")
    resp = Response(encrypted_token, 200)
    # resp.set_cookie('auth-token', encrypted_token, max_age=datetime.timedelta(days=30), httponly=True)
    return resp
    
@bp.route("/testauth")
# @flask_jwt.jwt_required()
@requires_auth
def test_auth():
    print("Ok")
    return Response("Ok", 200)
    # return flask_jwt.current_identity['username']