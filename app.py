from flask import Flask
import os
import hashlib
# import flask_jwt
import flask_bcrypt
from collections import namedtuple

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'posh.it.sqlite'),\
        JWT_AUTH_URL_RULE='/api/signin',
        JWT_AUTH_USERNAME_KEY='username',
        JWT_AUTH_PASSWORD_KEY='password',
    )
    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)
    os.makedirs(app.instance_path, exist_ok=True) #silently fail if it does happen to exist
    import db
    db.init_app(app)
    import api

    #jwt+bcrypt stuff
    app.bcrypt = flask_bcrypt.Bcrypt(app)

    # def jwt_identify(payload):
    #     print(payload)
    #     username = payload['username']
    #     dbo = db.get_db()
    #     table = dbo.cursor()
    #     return table.execute('SELECT * FROM user WHERE username=?', (username,)).fetchone()
    
    # jwt_auth = flask_jwt.JWT(app, sign_in, jwt_identify)
    app.register_blueprint(api.bp)

    return app
