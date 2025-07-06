from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage

import requests
import json
import os
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

PHOTO_BUCKET=os.environ["GCLOUD_STORAGE_BUCKET"]

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

client = datastore.Client()

BUSINESSES = "businesses"

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
DOMAIN = os.environ["DOMAIN"]
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
        raise AuthError({"Error": "Unauthorized"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"Error": "Unauthorized"}, 401)
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


@app.route('/')
def index():
    return "Please navigate to /users to use this API"\

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        
# Generate a JWT from the Auth0 domain and return it
@app.route('/users/login', methods=['POST'])
def login_user():

    content = request.get_json()

    if not content or "username" not in content or "password" not in content:
        return jsonify({"Error": "The request body is invalid"}), 400
    
    username = content["username"]
    password = content["password"]

    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
    }

    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    
    response = requests.post(url, json=body, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        return jsonify({"token": token_data.get("id_token")}), 200
    else:
        return jsonify({"Error": "Unauthorized"}), 401

@app.route('/users', methods=['GET'])
def get_all_users():
    # Verify JWT and extract payload
    payload = verify_jwt(request)

    # Extract sub from JWT and use it to fetch the user from Datastore
    sub = payload.get("sub")
    if not sub:
        return jsonify({"Error": "The JWT is missing or invalid"}), 401

    # Query for user with this sub
    query = client.query(kind="users")
    query.add_filter("sub", "=", sub)
    result = list(query.fetch())

    if not result:
        return jsonify({"Error": "Unauthorized"}), 403

    user = result[0]
    if user.get("role") != "admin":
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # If admin, fetch all users
    all_users_query = client.query(kind="users")
    all_users = list(all_users_query.fetch())

    # Only include id, role, sub for each user
    users_response = []
    for u in all_users:
        users_response.append({
            "id": u.id,  
            "role": u.get("role"),
            "sub": u.get("sub")
        })

    return jsonify(users_response), 200

@app.route("/users/<int:id>/avatar", methods=["POST"])
def upload_user_avatar(id):
    try:
        # Check file key
        if "file" not in request.files:
            return jsonify({"Error": "The request body is invalid"}), 400
        file = request.files["file"]

        # Verify JWT
        payload = verify_jwt(request)

        # Fetch user from Datastore
        key = client.key("users", id)
        user = client.get(key)

        if not user or user["sub"] != payload["sub"]:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Upload avatar to GCS
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(os.environ["GCLOUD_STORAGE_BUCKET"])
        blob = bucket.blob(f"{id}.png")
        file.seek(0)
        blob.upload_from_file(file, content_type="image/png")

        return jsonify({
            "avatar_url": f"{request.host_url}users/{id}/avatar"
        }), 200

    except Exception as e:
        print(e)
        return jsonify({"Error": "Unauthorized"}), 401

@app.route("/users/<int:id>/avatar", methods=["GET"])
def get_user_avatar(id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
        token_user_id = payload.get('sub')

        # Fetch user from Datastore
        key = client.key("users", id)
        user = client.get(key)

        # Check if user exists and token matches JWT
        if not user:
            return jsonify({"Error": "User not found"}), 404

        if user.get("sub") != token_user_id:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Check for avatar file
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(os.environ["GCLOUD_STORAGE_BUCKET"])
        blob = bucket.blob(f"{id}.png")

        if not blob.exists(storage_client):
            return jsonify({"Error": "Not found"}), 404

        # Stream file 
        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)

        return send_file(
            file_obj,
            mimetype="image/png",
            as_attachment=False,
            download_name="avatar.png"
        )

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route("/users/<int:id>/avatar", methods=["DELETE"])
def delete_user_avatar(id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
        token_user_id = payload.get('sub')

        # Fetch user from Datastore
        key = client.key("users", id)
        user = client.get(key)

        # Check if user exists and token matches
        if not user:
            return jsonify({"Error": "User not found"}), 404

        if user.get("sub") != token_user_id:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Check if file exists
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(os.environ["GCLOUD_STORAGE_BUCKET"])
        blob = bucket.blob(f"{id}.png")

        if not blob.exists(storage_client):
            return jsonify({"Error": "Not found"}), 404

        # Delete the file
        blob.delete()
        return '', 204

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route("/courses", methods=["POST"])
def create_course():
    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_sub = payload.get("sub")

        # Confirm user is an admin
        query = client.query(kind="users")
        query.add_filter("sub", "=", user_sub)
        user_results = list(query.fetch())

        if not user_results or user_results[0].get("role") != "admin":
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Parse and validate request body
        content = request.get_json()
        required_fields = ["subject", "number", "title", "term", "instructor_id"]
        if not all(field in content for field in required_fields):
            return jsonify({"Error": "The request body is invalid"}), 400

        # Confirm instructor_id maps to a valid instructor
        instructor_key = client.key("users", content["instructor_id"])
        instructor = client.get(instructor_key)

        if not instructor or instructor.get("role") != "instructor":
            return jsonify({"Error": "The request body is invalid"}), 400

        # Create course entity
        course = datastore.Entity(key=client.key("courses"))
        course.update({
            "subject": content["subject"],
            "number": content["number"],
            "title": content["title"],
            "term": content["term"],
            "instructor_id": content["instructor_id"]
        })
        client.put(course)

        # Construct and return response
        course_id = course.key.id
        response = {
            "id": course_id,
            "subject": course["subject"],
            "number": course["number"],
            "title": course["title"],
            "term": course["term"],
            "instructor_id": course["instructor_id"],
            "self": f"{request.host_url}courses/{course_id}"
        }

        return jsonify(response), 201

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route("/courses", methods=["GET"])
def get_all_courses():
    # Set pagination variables
    offset = int(request.args.get("offset", 0))
    limit = int(request.args.get("limit", 3))  # Default to 3 if not explicitly provided

    # Query all courses ordered by subject
    query = client.query(kind="courses")
    query.order = ["subject"]
    results = list(query.fetch(offset=offset, limit=limit))

    # Format each course into JSON response
    course_list = []
    for course in results:
        course_list.append({
            "id": course.key.id,
            "subject": course["subject"],
            "number": course["number"],
            "title": course["title"],
            "term": course["term"],
            "instructor_id": course["instructor_id"],
            "self": f"{request.host_url}courses/{course.key.id}"
        })

    # Add 'next' link if there may be more courses
    next_offset = offset + limit
    next_query = client.query(kind="courses")
    next_query.order = ["subject"]
    next_page = list(next_query.fetch(offset=next_offset, limit=1))  # Check for more entries

    response = {
        "courses": course_list
    }

    if next_page:
        response["next"] = f"{request.host_url}courses?offset={next_offset}&limit={limit}"

    return jsonify(response), 200

@app.route('/courses/<int:id>', methods=['GET'])
def get_course_by_id(id):
    # Retrieve the course by ID
    course_key = client.key("courses", id)
    course = client.get(course_key)

    # Handle course not found
    if course is None:
        return jsonify({"Error": "Not found"}), 404

    # Build and return response without students
    response = {
        "id": course.key.id,
        "subject": course["subject"],
        "number": course["number"],
        "title": course["title"],
        "term": course["term"],
        "instructor_id": course["instructor_id"],
        "self": f"{request.host_url}courses/{course.key.id}"
    }

    return jsonify(response), 200

@app.route('/courses/<int:id>', methods=['PATCH'])
def update_course(id):
    content = request.get_json()

    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_sub = payload.get("sub")

        # Retrieve course
        course_key = client.key("courses", id)
        course = client.get(course_key)

        # If course not found, return 403
        if course is None:
            return jsonify({"Error": "Course not found"}), 403

        # Check if user is admin
        query = client.query(kind="users")
        query.add_filter("sub", "=", user_sub)
        user_results = list(query.fetch())

        if not user_results or user_results[0].get("role") != "admin":
            return jsonify({"Error": "You don't have permission to update this course"}), 403

        # If instructor_id is being updated, validate instructor
        if "instructor_id" in content:
            instr_key = client.key("users", content["instructor_id"])
            instructor = client.get(instr_key)

            if not instructor or instructor.get("role") != "instructor":
                return jsonify({"Error": "Invalid instructor ID"}), 400

        # Apply partial update
        for field in ["subject", "number", "title", "term", "instructor_id"]:
            if field in content:
                course[field] = content[field]

        # Save updated entity
        client.put(course)

        # Build and return response
        updated = {
            "id": course.key.id,
            "subject": course["subject"],
            "number": course["number"],
            "title": course["title"],
            "term": course["term"],
            "instructor_id": course["instructor_id"],
            "self": f"{request.host_url}courses/{course.key.id}"
        }

        return jsonify(updated), 200

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route('/courses/<int:id>', methods=['DELETE'])
def delete_course(id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_sub = payload.get('sub')

        # Get user info and check if admin
        query = client.query(kind="users")
        query.add_filter("sub", "=", user_sub)
        users = list(query.fetch())

        if not users or users[0].get("role") != "admin":
            return jsonify({"Error": "You don't have permission to delete this course"}), 403

        # Retrieve the course
        course_key = client.key("courses", id)
        course = client.get(course_key)

        if not course:
            return jsonify({"Error": "Course not found"}), 403

        # Unenroll all students enrolled in the course
        enroll_query = client.query(kind="enrollments")
        enroll_query.add_filter("course_id", "=", id)
        enrollments = list(enroll_query.fetch())

        for enrollment in enrollments:
            client.delete(enrollment.key)

        # Delete the course
        client.delete(course_key)

        # Return no content
        return '', 204

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route('/courses/<int:id>/students', methods=['PATCH'])
def update_enrollment(id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_id = payload.get('sub')

        # Get course
        course_key = client.key("courses", id)
        course = client.get(course_key)

        if course is None:
            return jsonify({"Error": "Course not found"}), 403

        # Fetch user role
        query = client.query(kind="users")
        query.add_filter("sub", "=", user_id)
        results = list(query.fetch())

        if not results:
            return jsonify({"Error": "Permission denied"}), 403

        user = results[0]
        user_role = user.get("role")
        user_db_id = user.key.id

        # Allow only admin or the instructor of this course
        if user_role != "admin" and course.get("instructor_id") != user_db_id:
            return jsonify({"Error": "Permission denied"}), 403

        # Get and validate request body
        content = request.get_json()
        add_ids = content.get("add", [])
        remove_ids = content.get("remove", [])

        if set(add_ids) & set(remove_ids):
            return jsonify({"Error": "Enrollment data is invalid"}), 409

        # Validate all student IDs in both lists
        all_ids = set(add_ids + remove_ids)
        for sid in all_ids:
            student_key = client.key("users", sid)
            student = client.get(student_key)
            if not student or student.get("role") != "student":
                return jsonify({"Error": "Enrollment data is invalid"}), 409

        # Initialize enrollment list if not present
        if "enrollment" not in course:
            course["enrollment"] = []

        # Add valid students
        for sid in add_ids:
            if sid not in course["enrollment"]:
                course["enrollment"].append(sid)

        # Remove valid students
        for sid in remove_ids:
            if sid in course["enrollment"]:
                course["enrollment"].remove(sid)

        client.put(course)
        return "", 200

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error during enrollment update:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route('/courses/<int:id>/students', methods=['GET'])
def get_course_enrollment(id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_sub = payload.get('sub')

        # Get course by ID
        course_key = client.key("courses", id)
        course = client.get(course_key)

        if not course:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Get user from Datastore
        query = client.query(kind="users")
        query.add_filter("sub", "=", user_sub)
        users = list(query.fetch())

        if not users:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        user = users[0]

        # Check if user is admin or instructor for this course
        if user.get("role") == "admin":
            pass  
        elif user.get("role") == "instructor" and user.key.id == course.get("instructor_id"):
            pass  
        else:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Get enrolled students
        enrolled_students = course.get("enrollment", [])

        return jsonify(enrolled_students), 200

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

@app.route('/users/<int:id>', methods=['GET'])
def get_a_user(id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
        requester_sub = payload.get('sub')

        # Get user from Datastore
        key = client.key("users", id)
        user = client.get(key)

        if not user:
            return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Check if requester is this user or an admin
        if user.get('sub') != requester_sub:
            query = client.query(kind="users")
            query.add_filter("sub", "=", requester_sub)
            requester = list(query.fetch())
            if not requester or requester[0].get("role") != "admin":
                return jsonify({"Error": "You don't have permission on this resource"}), 403

        # Check for avatar existence
        storage_client = storage.Client()
        bucket = storage_client.bucket(os.environ["GCLOUD_STORAGE_BUCKET"])
        blob = bucket.blob(f"{id}.png")
        has_avatar = blob.exists(storage_client)

        # Build base response
        response = {
            "id": id,
            "role": user.get("role"),
            "sub": user.get("sub")
        }

        if has_avatar:
            response["avatar_url"] = f"{request.host_url}users/{id}/avatar"

        # Add courses if role is instructor or student
        if user.get("role") in ["instructor", "student"]:
            query = client.query(kind="courses")
            courses = list(query.fetch())

            if user.get("role") == "instructor":
                response["courses"] = [
                    f"{request.host_url}courses/{c.key.id}"
                    for c in courses if c.get("instructor_id") == id
                ]
            elif user.get("role") == "student":
                response["courses"] = [
                    f"{request.host_url}courses/{c.key.id}"
                    for c in courses if id in c.get("enrollment", [])
                ]

        return jsonify(response), 200

    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401
    except Exception as e:
        print("Unexpected error:", e)
        return jsonify({"Error": "Server error"}), 500

