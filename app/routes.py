from flask import Blueprint, request, jsonify, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash
from app import db  # Correctly importing db from the app module
from app.models import User, ClinicTeam, ClinicRoles, ClinicProviders, Clinic, ApiKey, APILog, Role
import random, secrets
import string
import re
import uuid
from datetime import datetime, timedelta
from functools import wraps
from app.models import ApiKey, APILog
import jwt
from app.util.decorators import validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard, log_api_access



main = Blueprint('main', __name__)

def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))

# logs creation for every api access
def log_api_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Retrieve the API key
            api_key = request.headers.get('x-api-key', 'Unknown')

            # Determine the system name
            system = ApiKey.query.filter_by(api_key=api_key).first()
            system_name = system.system_name if system else 'Unknown System'

            # Call the actual function
            response = f(*args, **kwargs)

            # Handle tuple responses
            if isinstance(response, tuple):
                response_body, status_code = response[0], response[1]
            else:
                status_code = response.status_code

            # Log API access
            log_entry = APILog(
                system_name=system_name,
                endpoint=request.path,
                method=request.method,
                status_code=status_code,
                accessed_at=datetime.utcnow()
            )

            # Save log entry to the database
            db.session.add(log_entry)
            db.session.commit()

            return response
        except Exception as e:
            # Handle errors gracefully
            db.session.rollback()
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

    return decorated_function

# team member add
# @main.route('/api/add_team_member', methods=['POST'])
# @log_api_access
# def add_team_member():
#     # Extract API key from headers
#     api_key = request.headers.get('X-API-Key')

#     # Validate API key
#     if not api_key:
#         return jsonify({'error': 'API key is required.'}), 401
    
#     valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
#     if not valid_key:
#         return jsonify({'error': 'Invalid or inactive API key.'}), 403

#     # Extract data from request body
#     data = request.get_json()
#     name = data.get('name')
#     email = data.get('email')
#     role = data.get('role')
#     designation = data.get('designation')
#     password = data.get('password')
#     clinic_id = 3  # Example clinic ID
#     invited_by_id = 3  # Example invited_by_id

#     # Generate an invitation token
#     invitation_token = str(uuid.uuid4())

#     # Validate input fields
#     if not all([name, email, role, designation, password]):
#         return jsonify({'error': 'All fields are required.'}), 400

#     # Check if the user already exists
#     user = User.query.filter_by(email=email).first()

#     if user:
#         # Check if the user is already in the clinic team
#         clinic_member = ClinicTeam.query.filter_by(email=email).first()
#         if clinic_member:
#             clinic_member.user_id = user.id
#             clinic_member.clinic_id = clinic_id
#             clinic_member.invited_by_id = invited_by_id
#             clinic_member.status = 'active'
#             db.session.commit()
#             return jsonify({'message': 'User already exists and has been updated in the clinic team.'}), 200
#         else:
#             # Add the user to the clinic team
#             new_clinic_member = ClinicTeam(
#                 user_id=user.id,
#                 email=email,
#                 role=role,
#                 designation=designation,
#                 clinic_id=clinic_id,
#                 invited_by_id=invited_by_id,
#                 status='active',
#                 invitation_token=invitation_token
#             )
#             db.session.add(new_clinic_member)
#             db.session.commit()
#             return jsonify({'message': 'User has been added to the clinic team.'}), 201
#     else:
#         # Create a new user
#         hashed_password = generate_password_hash(password)
#         new_user = User(name=name, email=email, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()

#         # Add the new user to the clinic team
#         new_clinic_member = ClinicTeam(
#             user_id=new_user.id,
#             email=email,
#             role=role,
#             designation=designation,
#             clinic_id=clinic_id,
#             invited_by_id=invited_by_id,
#             status='active',
#             invitation_token=invitation_token
#         )
#         db.session.add(new_clinic_member)
#         db.session.commit()

#         return jsonify({'message': 'New user and clinic team member created successfully.'}), 201




SECRET_KEY = "1234"  # Replace with a secure secret key

# @main.route('/api/login', methods=['POST'])
# def login():
#     # Extract API key from the request headers
#     api_key = request.headers.get('x-api-key')

#     # Validate API key
#     if not api_key:
#         return jsonify({'error': 'API key is required.'}), 401

#     # Check if the provided API key exists in the database and is active
#     valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
#     if not valid_key:
#         return jsonify({'error': 'Invalid or inactive API key.'}), 403

#     # Get data from request
#     data = request.get_json()
#     email = data.get('email')
#     password = data.get('password')

#     # Check if email and password are provided
#     if not email or not password:
#         return jsonify({'error': 'Email and password are required.'}), 400

#     # Query the User table to find the user by email
#     user = db.session.query(User).filter_by(email=email).first()

#     # Check if the user exists and verify the password
#     if user and check_password_hash(user.password, password):
#         user_id = user.id
#         user_role_id = user.role_id  # Use role_id directly
#         user_name = user.name

#         # Generate a JWT token for the user (Bearer Token logic)
#         token = jwt.encode({
#             'user_id': user_id,
#             'exp': datetime.utcnow() + timedelta(hours=12)
#         }, SECRET_KEY, algorithm='HS256')

#         # Set session data
#         session['user_id'] = user_id
#         session['user_name'] = user_name
#         session['role_id'] = user_role_id  # Store role_id in session

#         # Fetch the role name using role_id
#         user_role = Role.query.filter_by(id=user_role_id).first()
#         user_role_name = user_role.name if user_role else 'unknown'

#         session['user_role'] = user_role_name  # Store role name in session

#         # Role-specific logic for redirection
#         redirect_url = '/dashboard/index/Today'
#         if user_role_name == 'clinic':
#             clinic_team_member = ClinicTeam.query.filter_by(user_id=user_id).first()
#             if clinic_team_member:
#                 session['clinic_id'] = clinic_team_member.clinic_id
#                 redirect_url = f'/{clinic_team_member.role}_dashboard'
#             else:
#                 clinic = Clinic.query.filter_by(user_id=user_id).first()
#                 if clinic:
#                     session['clinic_id'] = clinic.id
#                 redirect_url = '/clinic_dashboard'
#         elif user_role_name == 'admin':
#             redirect_url = '/admin_dashboard'
#         elif user_role_name == 'billing':
#             redirect_url = '/billing/team_dashboard'

#         # Return response with JWT token and API token
#         return jsonify({
#             'message': 'Login successful',
#             'bearer_token': token,
#             'api_token': api_key,
#             'redirect': redirect_url
#         }), 200
#     else:
#         return jsonify({'error': 'Incorrect Credentials!!!'}), 401

# reset password
@main.route('/api/reset_password/<int:id>', methods=['POST'])
@log_api_access
def reset_password(id):
    # Extract API key from the request headers
    api_key = request.headers.get('x-api-key')

    # Validate API key
    if not api_key:
        return jsonify({'error': 'API key is required.'}), 401

    # Check if the provided API key exists in the database and is active
    valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
    if not valid_key:
        return jsonify({'error': 'Invalid or inactive API key.'}), 403

    # Extract data from the request body
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    # Validate input fields
    if not all([current_password, new_password, confirm_new_password]):
        return jsonify({'error': 'All fields are required.'}), 400

    # Password criteria: at least one uppercase, one lowercase, one number, and one special character
    password_criteria = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'

    if not re.match(password_criteria, new_password):
        return jsonify({
            'error': 'New password must be at least 8 characters long, contain at least one number, one letter, one uppercase letter, and one special character.'
        }), 400

    # Check if new password and confirm password match
    if new_password != confirm_new_password:
        return jsonify({'error': 'New password and confirm password do not match.'}), 400

    # Fetch the user from the database using the provided user_id (captured from the URL)
    user = User.query.filter_by(id=id).first()

    # Check if user exists
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    # Validate current password
    if not check_password_hash(user.password, current_password):
        return jsonify({'error': 'Current password is incorrect.'}), 401

    # Update password
    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({'message': 'Password has been reset successfully.'}), 200

# /////clinic roles create
# @main.route('/api/clinic_roles', methods=['POST'])
# @log_api_access
# def create_clinic_role():
#     """
#     API to create a new role in the clinic_roles table.
#     """

#     # Extract API key from the request headers
#     api_key = request.headers.get('x-api-key')

#     # Validate API key
#     if not api_key:
#         return jsonify({'error': 'API key is required.'}), 401

#     # Check if the provided API key exists in the database and is active
#     valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
#     if not valid_key:
#         return jsonify({'error': 'Invalid or inactive API key.'}), 403
#     data = request.get_json()

   
#     clinic_id = data.get('clinic_id')
#     name = data.get('name')
#     description = data.get('description', None)  # Optional field
#     status = data.get('status', 'active')  # Default to 'active'

   
#     if not clinic_id or not name:
#         return jsonify({'error': 'clinic_id and name are required fields.'}), 400

#     try:
       
#         new_role = ClinicRoles(
#             clinic_id=clinic_id,
#             name=name,
#             description=description,
#             status=status
#         )

     
#         db.session.add(new_role)
#         db.session.commit()

#         return jsonify({
#             'message': 'Role created successfully!',
#             'data': {
#                 'id': new_role.id,
#                 'clinic_id': new_role.clinic_id,
#                 'name': new_role.name,
#                 'description': new_role.description,
#                 'status': new_role.status,
#                 'created_at': new_role.created_at,
#                 'updated_at': new_role.updated_at,
#             }
#         }), 201

#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'error': str(e)}), 500


# clinic create
# clinic provider create

    
# get clinic roles
# @main.route('/api/clinic_roles', methods=['GET'])
# @log_api_access
# def get_active_clinic_roles():
#    # Extract API key from the request headers
#     api_key = request.headers.get('x-api-key')

#     # Validate API key
#     if not api_key:
#         return jsonify({'error': 'API key is required.'}), 401

#     # Check if the provided API key exists in the database and is active
#     valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
#     if not valid_key:
#         return jsonify({'error': 'Invalid or inactive API key.'}), 403
#     active_roles = db.session.query(ClinicRoles.name).filter_by(status='active').all()

#     if active_roles:
#         roles = [role[0] for role in active_roles]
#         return jsonify({
#             'message': 'Active clinic roles fetched successfully',
#             'roles': roles
#         }), 200
#     else:
#         return jsonify({'error': 'No active clinic roles found'}), 404

# get clinic providers


@main.route('/api/create_api_key', methods=['POST'])
# @log_api_access
def create_api_key():

    # Extract data from request body
    data = request.get_json()
    system_name = data.get('system_name')

    # Ensure system name is provided
    if not system_name:
        return jsonify({'error': 'System name is required.'}), 400

    # Generate a secure random API key
    new_api_key = secrets.token_hex(32)

    # Create an entry in the database
    api_key_entry = ApiKey(system_name=system_name, api_key=new_api_key, is_active=True)
    db.session.add(api_key_entry)
    db.session.commit()

    return jsonify({
        'message': 'API key created successfully.',
        'api_key': new_api_key
    }), 201
    
    
    # logs for every api accessed
    

@main.route("/validate_token", methods=["GET"])
@validate_bearer_token  # Apply the decorator here
def validate_token():
    # At this point, the token is already validated and user info is attached to `g.user`
    return jsonify({"message": "Success!", "user": g.user.name})