from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash,  check_password_hash
from app import db
from app.models import User, ApiKey, APILog, Role, Dashboard, ClinicTeam, ClinicRoles
from datetime import datetime
import pyotp
from sqlalchemy.orm import joinedload
from app.util.decorators import validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard, log_api_access, generate_otp  
import time
import requests
from dotenv import load_dotenv
import os
user = Blueprint('user', __name__)
load_dotenv()

# Access the environment variables
MAILGUN_API_KEY = os.getenv('MAILGUN_API_KEY')
MAILGUN_DOMAIN = os.getenv('MAILGUN_DOMAIN')
MAILGUN_API_URL = os.getenv('MAILGUN_API_URL')
# -------------------------------------------------------------------
# CREATE USER (POST /create_user)
# -------------------------------------------------------------------
@user.route('/create_user', methods=['POST'])
@validate_api_key
@log_api_access
def create_user():
    """Create a new user."""

    data = request.get_json()

    # Extract user input
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    role_id = data.get('role_id')
    dashboard_id = data.get('dashboard_id')
    user_image = data.get('user_image')

    # Validate user input
    required_fields = ['first_name', 'last_name', 'email', 'password', 'role_id', 'dashboard_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate role
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'error': 'Role not found'}), 400

    # Validate dashboard
    if dashboard_id:
        dashboard = Dashboard.query.get(dashboard_id)
        if not dashboard:
            return jsonify({'error': 'Dashboard not found'}), 400

    # Check if the email is already in use
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User with this email already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Generate OTP secret
    otp_secret = pyotp.random_base32()

    # Create new user
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        role_id=role_id,
        otp_secret=otp_secret,
        user_image=user_image,
        dashboard_id=dashboard_id
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred while creating the user: {str(e)}'}), 500

# -------------------------------------------------------------------
# GET ALL USERS (GET /users)
# -------------------------------------------------------------------
@user.route('/users', methods=['GET'])
def get_all_users():
    """
    Fetch all users, left-join to Role and Dashboard for extra info.
    """
    users_query = db.session.query(
        User,
        Role.name.label('name'),
        Dashboard.name.label('name')
    ).outerjoin(Role, User.role_id == Role.id
    ).outerjoin(Dashboard, User.dashboard_id == Dashboard.id)

    users = users_query.all()

    users_data = [
        {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'role_id': user.role_id,
            'role_name': role_name,
            'user_image': user.user_image,
            'dashboard_id': user.dashboard_id,
            'dashboard_name': dashboard_name,
        } for (user, role_name, dashboard_name) in users
    ]

    return jsonify(users_data), 200


# -------------------------------------------------------------------
# GET USER BY ID (GET /user/<user_id>)
# -------------------------------------------------------------------

@user.route('/user/<int:user_id>', methods=['GET'])
@validate_api_key
@log_api_access
def get_user(user_id):
    """Fetch user by ID, including role, dashboard, and user_role from clinic_team."""
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    # Fetch role
    role = Role.query.get(user.role_id)

    # Handle multiple dashboards if dashboard_id is an array
    dashboard_names = []
    if isinstance(user.dashboard_id, list):  # Check if it's an array
        dashboards = Dashboard.query.filter(Dashboard.id.in_(user.dashboard_id)).all()
        dashboard_names = [d.name for d in dashboards]
    else:
        dashboard = Dashboard.query.get(user.dashboard_id)
        if dashboard:
            dashboard_names.append(dashboard.name)

    # Fetch clinic_team entry for this user
    clinic_team = ClinicTeam.query.filter_by(user_id=user.id).first()
    
    # Fetch clinic_role name if available
    user_role_name = None
    if clinic_team:
        clinic_role = ClinicRoles.query.get(clinic_team.clinic_role_id)
        user_role_name = clinic_role.role_name if clinic_role else None

    user_data = {
        'id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'user_image': user.user_image,
        'email': user.email,
        'phone': user.phone,
        'address': user.address,
        'timezone': user.timezone,
        'role_id': user.role_id,
        'role_name': role.name if role else None,
        'dashboard_ids': user.dashboard_id if isinstance(user.dashboard_id, list) else [user.dashboard_id],
        'dashboard_names': dashboard_names,
        'user_role': user_role_name  # Added user_role from ClinicRoles
    }

    return jsonify(user_data), 200


# -------------------------------------------------------------------
# UPDATE USER (PUT /user/<user_id>)
# -------------------------------------------------------------------
@user.route('/user/<int:user_id>', methods=['PUT'])
@validate_api_key
@log_api_access
def update_user(user_id):
    """Update user with new data."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json() or {}

    # Validate the role_id if provided
    if 'role_id' in data:
        role = Role.query.get(data['role_id'])
        if not role:
            return jsonify({'error': f"Role with id {data['role_id']} not found"}), 404
        user.role_id = data['role_id']

    # Validate the dashboard_id if provided
    if 'dashboard_id' in data:
        dashboard = Dashboard.query.get(data['dashboard_id'])
        if not dashboard:
            return jsonify({'error': f"Dashboard with id {data['dashboard_id']} not found"}), 404
        user.dashboard_id = data['dashboard_id']

    # Update other user fields
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.user_image = data.get('user_image', user.user_image)
    user.address = data.get('address', user.address)
    user.userStatus = data.get('userStatus', user.userStatus)
    user.phone = data.get('phone', user.phone)
    user.timezone = data.get('timezone', user.timezone)

    if 'password' in data:
        user.password = generate_password_hash(data['password'])

    db.session.commit()

    return jsonify({'message': 'User updated successfully'}), 200

# -------------------------------------------------------------------
# DELETE USER (DELETE /user/<user_id>)
# -------------------------------------------------------------------
@user.route('/user/<int:user_id>', methods=['DELETE'])
@validate_api_key
@log_api_access
def delete_user(user_id):
    user_obj = User.query.filter_by(id=user_id).first()
    if not user_obj:
        return jsonify({'error': 'User not found.'}), 404

    db.session.delete(user_obj)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully.'}), 200


@user.route('/user/change_password/<int:user_id>', methods=['PUT'])
@validate_api_key
@log_api_access
def change_password(user_id):
    user_obj = User.query.filter_by(id=user_id).first()
    
    if not user_obj:
        return jsonify({'error': 'User not found.'}), 404

    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'error': 'Both old and new passwords are required.'}), 400

    # Check if old password matches
    if not check_password_hash(user_obj.password, old_password):
        return jsonify({'error': 'Incorrect old password.'}), 401

    # Hash new password and update it
    user_obj.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({'message': 'Password updated successfully.'}), 200


def send_otp_to_email(email, otp):
    """
    Function to send OTP to user email using Mailgun with a well-designed HTML template.
    """
    # Creating the HTML content for the email with a card design
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px;">
            <div style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); padding: 20px;">
                <h2 style="color: #2c3e50; text-align: center;">🔐 Secure OTP for Verification</h2>
                <hr style="border: none; height: 1px; background-color: #ddd; margin: 20px 0;">
                
                <div style="text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 8px;">
                    <h1 style="color: #e74c3c; font-size: 32px; margin: 0;">{otp}</h1>
                    <p style="color: #7f8c8d; font-size: 16px; margin-top: 10px;">
                        Use this OTP to reset your password. It expires in <strong>10 minutes</strong>.
                    </p>
                </div>
                
                <p style="font-size: 16px; color: #34495e; text-align: center; margin-top: 20px;">
                    If you did not request this, please ignore this email.
                </p>
                
                <hr style="border: none; height: 1px; background-color: #ddd; margin: 20px 0;">
                <p style="font-size: 12px; color: #95a5a6; text-align: center;">
                    📧 This is an automated email. Please do not reply.
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    # Data to be sent with the API request
    data = {
        "from": "support@360dentalbillingsolutions.com",
        "to": email,
        "subject": "🔑 Your OTP for Password Reset",
        "html": html_message  # HTML content for the email
    }

    # Get API URL and API Key from environment variables
    MAILGUN_API_KEY = os.getenv('MAILGUN_API_KEY')
    MAILGUN_API_URL = os.getenv('MAILGUN_API_URL')

    # Making the API request to send the email
    response = requests.post(
        MAILGUN_API_URL,
        auth=("api", MAILGUN_API_KEY),
        data=data
    )

    if response.status_code == 200:
        print(f"✅ OTP email sent to {email}")
        return True
    else:
        print(f"❌ Failed to send OTP email to {email}. Error: {response.text}")
        return False

@user.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        # Get email from request
        email = request.json.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'No user found with this email'}), 404

        # Generate OTP
        otp = generate_otp()
        otp_expiry = int(time.time()) + 600  # OTP valid for 10 minutes

        # Store OTP and expiry in user record
        user.otp_password = otp
        user.otp_expiry = otp_expiry
        db.session.commit()

        # Send OTP via email
        if send_otp_to_email(email, otp):
            return jsonify({'message': 'OTP sent to your email'}), 200
        else:
            return jsonify({'error': 'Failed to send OTP'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@user.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        # Get OTP and new password from request
        otp = request.json.get('otp')
        new_password = request.json.get('new_password')
        
        if not otp or not new_password:
            return jsonify({'error': 'OTP and new password are required'}), 400

        # Get the user associated with the OTP
        user = User.query.filter_by(otp_password=otp).first()

        if not user:
            return jsonify({'error': 'Invalid OTP'}), 400
        
        # Check if OTP is expired
        if int(time.time()) > user.otp_expiry:
            return jsonify({'error': 'OTP has expired'}), 400
        
        # Hash the new password
        hashed_password = generate_password_hash(new_password)
        
        # Update the user's password
        user.password = hashed_password
        user.reset_otp = None  # Clear the OTP after use
        user.otp_expiry = None  # Clear OTP expiry
        db.session.commit()

        return jsonify({'message': 'Password updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def generate_otp():
    """
    Generate a random 6-digit OTP.
    """
    from random import randint
    otp = randint(100000, 999999)
    return otp


@user.route("/user/email/<string:full_name>", methods=["GET"])
def get_email_by_full_name(full_name):
    try:
        # Split full_name into first_name and last_name
        name_parts = full_name.split()
        if len(name_parts) < 2:
            return jsonify({"error": "Please provide both first and last name"}), 400

        first_name = name_parts[0]
        last_name = " ".join(name_parts[1:])  # Handle multi-part last names

        # Query user by first and last name
        user = User.query.filter_by(first_name=first_name, last_name=last_name).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({"email": user.email}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@user.route('/admin_change_password', methods=['POST'])
@validate_api_key
@validate_bearer_token
# @validate_user_role(['panacea', 'credentialing', 'admin'])
# @validate_user_dashboard(['auth'])
@log_api_access
def admin_change_password():
    data = request.get_json()
    # Ensure all required parameters are provided
    if not data or 'user_id' not in data or 'new_password' not in data or 'confirm_password' not in data:
        return jsonify({
            "error": "Missing required parameters: user_id, new_password, and confirm_password"
        }), 400

    # Check if new_password and confirm_password match
    if data['new_password'] != data['confirm_password']:
        return jsonify({
            "error": "New password and confirm password do not match"
        }), 400

    user_id = data['user_id']
    new_password = data['new_password']

    # TODO: Add admin authentication and authorization checks here

    # Fetch the user from the database
    user_obj = User.query.filter_by(id=user_id).first()
    if not user_obj:
        return jsonify({"error": "User not found"}), 404

    # Hash the new password and update the user record
    user_obj.password = generate_password_hash(new_password)
    
    try:
        db.session.commit()
        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "error": "An error occurred while updating password",
            "details": str(e)
        }), 500
