import os, jwt, datetime
from flask import jsonify,abort,session
from functools import wraps

generate = lambda x: os.urandom(x).hex()
key = generate(50)
ALLOWED_EXTENSIONS = {'png'}

user_profile_schema = {
    "type": "object",
    "properties": {
        "full_name": {"type": "string"},
        "issn": {"type": "string"},
        "qualification": {"type": "string", "enum": ["BPC", "HSPC", "SSPC"]},
        "iexp": {"type": "string"},
        "bio": {"type": "string"},
        "bots": {
            "type": "array",
            "maxItems": 9,
            "items": {"type": "string", "maxLength": 10},
        },
        "meta_desc": {"type": "string"},
        "meta_keywords": {"type": "string"},
    },
    "required": [
        "full_name",
        "issn",
        "qualification",
        "iexp",
        "bio",
        "bots",
        "meta_desc",
        "meta_keywords",
    ],
}

def response(message):
    return jsonify({'message': message})

def create_JWT(username):
    token_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=360)
    
    encoded = jwt.encode(
        {
            'username': username,
            'exp': token_expiration
        },
        key,
        algorithm='HS256'
    )

    return encoded

def verify_JWT(token):
    try:
        token_decode = jwt.decode(
            token,
            key,
            algorithms='HS256'
        )

        return token_decode
    except:
        return abort(400, 'Invalid token!')

def is_authenticated(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = session.get('auth')

        if not token:
            return abort(401, 'Unauthorised access detected!')

        user = verify_JWT(token)
 
        return f(user, *args, **kwargs)

    return decorator

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS