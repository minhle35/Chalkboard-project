from flask import Flask, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
import re
# import secrets

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

LODGINGS = "lodgings"

# Update the values of the following 3 variables
CLIENT_ID = 't9InHvvDdPZ6XyKuDYFaQ1fmKWsZlBV0'
CLIENT_SECRET = 'mWf2sW5YoWUcfT6UqFx1nWuuqNuMXR81-pfYQ0fzPtRO_B_PdPaVXM-tJ4cqeinS'
DOMAIN = 'dev-4ega266k2nbz02by.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


# @app.route('/')
# def index():
#     return "Please navigate to /lodgings to use this API"\

# Create a lodging if the Authorization header contains a valid JWT
# @app.route('/lodgings', methods=['POST'])
# def lodgings_post():
#     if request.method == 'POST':
#         payload = verify_jwt(request)
#         content = request.get_json()
#         new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
#         new_lodging.update({"name": content["name"], "description": content["description"],
#           "price": content["price"]})
#         client.put(new_lodging)
#         return jsonify(id=new_lodging.key.id)
#     else:
#         return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
# @app.route('/decode', methods=['GET'])
# def decode_jwt():
#     payload = verify_jwt(request)
#     return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    try:
        content = request.get_json()
        username = content["username"]
        password = content["password"]
    except Exception:
        return jsonify({"error": "Request body is invalid"}), 400
    if not username or not password:
        return jsonify({"error": "Request body is invalid"}), 400


    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    try:
        response = requests.post(url, json=body, headers=headers)
        response.raise_for_status()

    except requests.exceptions.HTTPError as http_error:
        if response.status_code == 403:
            return jsonify({"error": "Username and/or password is incorrect"}), 401
        return jsonify({"error": "Authentication failed", "details": str(http_error)}), 500
    except Exception as e:
        return jsonify({"error": "Authentication failed", "details": str(e)}), 500

    token_data = response.json()
    id_token = token_data.get("id_token")
    if not id_token:
        return jsonify({"error": "Authentication failed", "details": "id_token not found"}), 500
    return jsonify({"token": id_token}), 200

@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        # Verify the JWT
        payload = verify_jwt(request)

        # Extract the subject (sub) from the JWT payload
        user_sub = payload["sub"]

        # Query the Datastore for the user's role
        query = client.query(kind="users")
        query.add_filter(filter=("sub", "=", user_sub))
        all_users = list(query.fetch())
        if not all_users:
            return jsonify({"error": "User not found"}), 401

        pattern = r"<Entity\('users', (\d+)\) \{.*'sub': '([^']+)', 'role': '([^']+)'\}>"
        response_data = []
        has_admin = False
        for user in all_users:
            match = re.search(pattern, str(user))
            if match:
                user_id = match.group(1)
                sub = match.group(2)
                role = match.group(3)
                response_data.append({"id": user_id, "role": role, "sub": sub})
                if role == "admin":
                    has_admin = True

        if not has_admin:
            return jsonify({"error": "Forbidden: Admin access required"}), 403

        return jsonify(response_data), 200

    except AuthError as e:
        return handle_auth_error(e)
    except Exception as e:
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

