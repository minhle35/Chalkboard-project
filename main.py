from flask import Flask, request, jsonify, Response
from google.cloud import datastore, storage
import datetime
import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
import re
import os
from collections import deque
from dotenv import load_dotenv

def generate_signed_url(bucket_name, blob_name, expiration_minutes=15):
    """Generate a signed URL for accessing a private object in Cloud Storage."""
    storage_client = storage.Client()

    # Get the bucket and blob
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    # Set the expiration time for the signed URL
    expiration = datetime.timedelta(minutes=expiration_minutes)

    # Generate the signed URL
    signed_url = blob.generate_signed_url(expiration=expiration, method="GET")

    return signed_url
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

client = datastore.Client()
storage_client = storage.Client()

LODGINGS = "lodgings"

# Update the values of the following 3 variables
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = os.getenv("DOMAIN")
BUCKET_NAME = os.getenv("BUCKET_NAME")
ALGORITHMS = ["RS256"]
APP_HOST = os.getenv("APP_HOST")
APP_PORT = os.getenv("APP_PORT")
APP_URL = os.getenv("APP_URL")

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
def verify_jwt(request, user_id=None):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header"}, 401)

    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"Error": "Unauthorized"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"Error": "Unauthorized"}, 401)
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
            # extract 'sub' from token payload
            token_sub = payload.get('sub')
            query = client.query(kind="users")
            query.add_filter("sub", "=", token_sub)
            results_user_id = list(query.fetch())[0].id
            if user_id:
                if str(results_user_id) != str(user_id):
                    raise AuthError({"Error": "You don't have permission on this resource"}, 403)
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except AuthError:
            raise
        except Exception:
            raise AuthError({"Error": "Unauthorized"}, 401)
        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


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
    except KeyError:
        return jsonify({"Error": "The request body is invalid"}), 400

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
            return jsonify({"Error": "Unauthorized"}), 401
        return jsonify({"error": "Authentication failed", "details": str(http_error)}), 500
    except Exception as e:
        return jsonify({"error": "Authentication failed", "details": str(e)}), 500

    token_data = response.json()
    id_token = token_data.get("id_token")
    if not id_token:
        return jsonify({"error": "Authentication failed", "details": "id_token not found"}), 500
    return jsonify({"token": id_token}), 200

def user_match(user_info_list, user_id_target=None):
    """
    Matches users from a list of Datastore entities based on user_id_target.

    Args:
        user_info_list: List of user entities from Datastore.
        user_id_target: The ID of the user to search for (optional).

    Returns:
        has_admin (bool): Whether an admin exists in the list.
        response_list (list): All user info if user_id_target is not provided.
        target_user_info (dict or None): Target user's info if user_id_target is provided.
    """

    pattern = r"<Entity\('users', (\d+)\) \{.*'sub': '([^']+)', 'role': '([^']+)'\}>"
    response_data = []

    for user in user_info_list:
        match = re.search(pattern, str(user))
        if match:
            user_id = match.group(1)
            sub = match.group(2)
            role = match.group(3)
            response_data.append({"id": user_id, "role": role, "sub": sub})

    if user_id_target:
        # Filter response_data for the target user ID
        target_user_info = next((u for u in response_data if u["id"] == user_id_target), None)
        return None, target_user_info

    return response_data, None


@app.route('/users', methods=['GET'])
def get_all_users():
    """_summary_: function to retrieve ALL users from the users kind
    in Google Cloud Datastore. The response is filtered by the sub
    field from the authenticated user's JWT.
    """
    try:
        # Verify the JWT
        payload = verify_jwt(request)
        if not payload["nickname"].startswith("admin"):
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Query the Datastore for the user's role
        query = client.query(kind="users")
        all_users = list(query.fetch())
        if not all_users:
            return jsonify({"error": "No users found"}), 401
        user_info_list, _ = user_match(all_users)

        return jsonify(user_info_list), 200

    except AuthError as e:
        return handle_auth_error(e)
    except Exception as e:
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500


@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """_summary_: function to retrieve a specific user from the users kind

    Args:
        user_id (_type_): _description_

    Returns:
        _type_: _description_
    """
    try:
        payload = verify_jwt(request, user_id=user_id)
        key = client.key("users", int(user_id))
        user_entity = client.get(key)
        if not user_entity:
            return jsonify({"Error": "Not found"}), 401

        # Extract details from the dictionary-like entity
        user_id = str(user_entity.key.id)
        sub = user_entity.get('sub', None)
        role = user_entity.get('role', None)
        avatar_url = user_entity.get('avatar_url', None)

        if role in ("instructor","student"):
            courses = []
            if avatar_url:
                avatar_url = f"http://{APP_HOST}:{APP_PORT}/users/{user_id}/avatar"
                return jsonify({"avatar_url": avatar_url, "courses": courses, "id": user_id, "role": role, "sub": sub}), 200
            return jsonify({"courses": [], "id": user_id, "role": role, "sub": sub}), 200
        if role == "admin":
            if avatar_url:
                return jsonify({"avatar_url": avatar_url, "courses": [], "id": user_id, "role": role, "sub": sub}), 200

            return jsonify({"courses": [], "id": user_id, "role": role, "sub": sub}), 200

    except AuthError as e:
        return handle_auth_error(e)
    except Exception as e:
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

def upload_to_bucket(bucket_name, file, user_id):
    """Uploads the file to Cloud Storage and returns the public URL."""
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(f"{user_id}.png")

    # Upload file
    blob.upload_from_file(file, content_type="image/png")

    # Return the public URL
    return blob.name

@app.route('/users/<user_id>/avatar', methods=['POST'])
def update_avatar(user_id):
    print("Request header", request.headers)
    try:
        _ = verify_jwt(request, user_id=user_id)

        file = request.files['file']
        if file.filename == '' or 'file' not in request.files:
            return jsonify({"error": "Missing 'file' key in request"}, 400)

        file = request.files['file']
        if not file.filename.endswith(".png"):
            return jsonify({"error": "Bad Request: File must have a .png extension"}), 400

        # upload file to google cloud storage
        avatar_url = upload_to_bucket(BUCKET_NAME, file, user_id)

        # update avatar_url in datastore
        key = client.key("users", int(user_id))
        user_entity = client.get(key)
        if not user_entity:
            return jsonify({"error": "No Users found"}), 404
        user_entity['avatar_url'] = avatar_url
        client.put(user_entity)
        avatar_url = f"http://{APP_HOST}:{APP_PORT}/users/{user_id}/avatar"

        return jsonify({"avatar_url": avatar_url}), 200

    except AuthError as e:
        return handle_auth_error(e)
    except KeyError as _:
        return jsonify({"Error": "The request body is invalid"}), 400

@app.route('/users/<user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    """_summary_: function to retrieve an avatar from the users kind

    Args:
        user_id (str):

    Returns:
        result as json if error, otherwise download image and return with error code
    """
    try:
        _ = verify_jwt(request, user_id=user_id)

        key = client.key("users", int(user_id))
        user_entity = client.get(key)
        if not user_entity:
            return jsonify({"error": "No Users found"}), 404

        avatar_url = user_entity.get('avatar_url')
        if not avatar_url:
            return jsonify({"Error": "Not found"}), 404

        # In case we want to return a signed URL
        # signed_url = generate_signed_url(BUCKET_NAME, avatar_url)
        # return jsonify({"avatar_url": signed_url}), 200

        # Initialize Cloud Storage client
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(avatar_url)

        # Check if the blob exists
        if not blob.exists():
            return jsonify({"error": "Avatar file not found"}), 404

        # Download the file as bytes
        image_data = blob.download_as_bytes()

        # Return the image data directly with mime type headers
        return Response(image_data, mimetype="image/png")

    except AuthError as e:
        return handle_auth_error(e)

@app.route('/users/<user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    """_summary_: function to delete an avatar from the users kind

    Args:
        user_id (str): _description_

    Returns:
        error message
    """
    try:
        _ = verify_jwt(request, user_id=user_id)

        key = client.key("users", int(user_id))
        user_entity = client.get(key)
        if not user_entity:
            return jsonify({"error": "No Users found"}), 404

        avatar_url = user_entity.get('avatar_url')
        if not avatar_url:
            return jsonify({"Error": "Not found"}), 404

        # Delete the avatar file from Cloud Storage
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(avatar_url)

        blob.delete()

        #update avatar_url in datastore
        user_entity['avatar_url'] = ''
        client.put(user_entity)

        return jsonify({"message": "Avatar deleted successfully"}), 204
    except AuthError as e:
        return handle_auth_error(e)

@app.route('/courses', methods=['POST'])
def create_course():
    try:
        # Verify JWT
        payload = verify_jwt(request)
        print("Payload:", payload)
        if not payload.get("nickname").startswith("admin"):
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Parse the JSON request body
        data = request.get_json()
        required_fields = ["subject", "number", "title", "term", "instructor_id"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"Error": "The request body is invalid"}), 400

        # Validate instructor_id exists and is an instructor
        instructor_id = data["instructor_id"]
        instructor_key = client.key("users", int(instructor_id))
        instructor_entity = client.get(instructor_key)

        if not instructor_entity or instructor_entity.get("role") != "instructor":
            return jsonify({"Error": "The request body is invalid"}), 400

        # Create a new course entity
        course_key = client.key("courses")
        course_entity = datastore.Entity(key=course_key)
        course_entity.update({
            "subject": data["subject"],
            "number": data["number"],
            "title": data["title"],
            "term": data["term"],
            "instructor_id": instructor_id
        })

        # Save to Datastore
        client.put(course_entity)

        # Build the response
        course_id = course_entity.key.id
        response_data = {
            "id": course_id,
            "subject": data["subject"],
            "number": data["number"],
            "title": data["title"],
            "term": data["term"],
            "instructor_id": str(instructor_id),
            "self": f"{APP_URL}/courses/{course_id}"
        }

        return jsonify(response_data), 201

    except AuthError as e:
        return handle_auth_error(e)
    except Exception as e:
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

@app.route('/courses/<course_id>', methods=['GET'])
def get_course(course_id):

    # Get the course entity from Datastore
    course_key = client.key("courses", int(course_id))
    course_entity = client.get(course_key)

    if not course_entity:
        return jsonify({"Error": "Not found"}), 404

    # Build the response
    response_data = {
        "id": course_id,
        "subject": course_entity["subject"],
        "number": course_entity["number"],
        "title": course_entity["title"],
        "term": course_entity["term"],
        "instructor_id": str(course_entity["instructor_id"]),
        "self": f"{APP_URL}/courses/{course_id}"
    }

    return jsonify(response_data), 200

@app.route('/courses', methods=['GET'])
def get_all_courses():
    try:
        # Extract query parameters
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', 3))

        # Create a query for the "courses" kind, sorted by "subject"
        query = client.query(kind="courses")
        query.order = ["subject"]


        results_iter = query.fetch()
        all_courses = list(results_iter)

        # Apply offset and limit
        courses = all_courses[offset:offset + limit]

        # Convert courses into dictionaries
        courses_dict = [
            {
                "id": course.key.id,
                "instructor_id": course["instructor_id"],
                "number": course["number"],
                "self": f"{APP_URL}/courses/{course.key.id}",
                "subject": course["subject"],
                "term": course["term"],
                "title": course["title"],
            }
            for course in courses
        ]

        # Build the response
        total_courses = len(all_courses)
        response = {
            "courses": courses_dict,
        }

        # Add "next" URL if there are more results
        if offset + limit < total_courses:
            response["next"] = f"{APP_URL}/courses?limit={limit}&offset={offset + limit}"

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

if __name__ == '__main__':
    app.run(host=APP_HOST, port=APP_PORT, debug=True)

