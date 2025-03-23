from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import Clinic, User, ApiKey, APILog,ClinicTeam, Role, Dashboard
from datetime import datetime
from functools import wraps
import pyotp
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard


clinic = Blueprint('clinic', __name__)


# Add a new clinic
@clinic.route('/add_clinic', methods=['POST'])
@validate_api_key
# @validate_bearer_token
@log_api_access
def create_clinic():
    """Create a new clinic with a user."""

    data = request.get_json()

    # Validate request data
    required_fields = [
        'first_name',
        'last_name',
        'email',
        'address',
        'phone',
        'password',
        'confirm_password',
        'role_id',
        'dashboard_id'
    ]
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Extract request data
    first_name = data['first_name']
    last_name = data['last_name']
    email = data['email']
    address = data['address']
    phone = data['phone']
    password = data['password']
    confirm_password = data['confirm_password']
    role_id = data['role_id']
    dashboard_id = data.get('dashboard_id')

    # Validate role and dashboard
    if not Role.query.get(role_id):
        return jsonify({'error': 'Role not found'}), 400

    if dashboard_id and not Dashboard.query.get(dashboard_id):
        return jsonify({'error': 'Dashboard not found'}), 400

    # Validate password length and complexity
    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char.isupper() for char in password):
        return jsonify({'error': 'Password must be at least 8 characters long, contain at least one number, one letter, and one uppercase letter.'}), 400

    # Check if passwords match
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    # Check if the email already exists in the 'users' table
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)
    otp_secret = pyotp.random_base32()

    # Create a new User instance
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        phone=phone,
        password=hashed_password,
        address=address,
        otp_secret=otp_secret,
        role_id=role_id,
        dashboard_id=dashboard_id,
    )

    # Add the new user to the database
    try:
        db.session.add(new_user)
        db.session.commit()

        # Create the clinic for the new user
        user_id = new_user.id
        clinic_name = f'{first_name} {last_name} Clinic'
        timestamp = int(datetime.utcnow().timestamp())

        # Create a new Clinic instance
        new_clinic = Clinic(
            user_id=user_id,
            clinic_name=clinic_name,
            address=address,
            city='CityName',  # Replace with actual city if available
            state='StateName',  # Replace with actual state if available
            postal_code='00000',  # Replace with actual postal code if available
            phone=phone,
            timestamp=timestamp,
        )

        # Commit new clinic to the database
        db.session.add(new_clinic)
        db.session.commit()

        # Add the user to the clinic team
        new_clinic_member = ClinicTeam(
            user_id=user_id,
            first_name=first_name,
            last_name=last_name,
            email=email,
            clinic_role_id=1,  # Define the role of the user in the clinic //admin
            designation='Admin',  # Example designation
            phone=phone,
            address=address,
            clinic_id=new_clinic.id,
            invited_by_id=user_id,  # Set if applicable
            status='accepted',  # Define the status
            invitation_token=None  # If applicable
        )

        # Commit the new clinic member to the database
        db.session.add(new_clinic_member)
        db.session.commit()

        return jsonify({'message': 'Clinic and User created successfully', 'clinic_id': new_clinic.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

    
# Get a specific clinic by ID    
@clinic.route('/clinic/<int:id>', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def get_clinic_by_id(id):
    clinic = Clinic.query.get(id)
    
    if not clinic:
        return jsonify({'error': 'Clinic not found'}), 404
    
    return jsonify({
        'id': clinic.id,
        'user_id': clinic.user_id,
        'clinic_name': clinic.clinic_name,
        'address': clinic.address,
        'city': clinic.city,
        'state': clinic.state,
        'postal_code': clinic.postal_code,
        'phone': clinic.phone,
        'timestamp': clinic.timestamp
    })

# Get all clinics
@clinic.route('/clinic', methods=['GET'])
def get_all_clinics():
    clinics = Clinic.query.all()
    
    if not clinics:
        return jsonify({'message': 'No clinics found'}), 404

    clinics_list = []
    for clinic in clinics:
        clinics_list.append({
            'id': clinic.id,
            'user_id': clinic.user_id,
            'clinic_name': clinic.clinic_name,
            'address': clinic.address,
            'city': clinic.city,
            'state': clinic.state,
            'postal_code': clinic.postal_code,
            'phone': clinic.phone,
            'timestamp': clinic.timestamp
        })
    
    return jsonify({'clinics': clinics_list})

# Update a clinic
@clinic.route('/clinic/<int:id>', methods=['PUT'])
@validate_api_key
@validate_bearer_token
@log_api_access
def update_clinic(id):
    clinic = Clinic.query.get(id)

    if not clinic:
        return jsonify({'error': 'Clinic not found'}), 404

    data = request.get_json()

    # Optional: You can check for the fields to be updated
    clinic_name = data.get('clinic_name', clinic.clinic_name)
    address = data.get('address', clinic.address)
    city = data.get('city', clinic.city)
    state = data.get('state', clinic.state)
    postal_code = data.get('postal_code', clinic.postal_code)
    phone = data.get('phone', clinic.phone)

    clinic.clinic_name = clinic_name
    clinic.address = address
    clinic.city = city
    clinic.state = state
    clinic.postal_code = postal_code
    clinic.phone = phone
    clinic.timestamp = int(datetime.utcnow().timestamp())  # Update the timestamp

    try:
        db.session.commit()
        return jsonify({'message': 'Clinic updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Delete a clinic
@clinic.route('/clinic/<int:id>', methods=['DELETE'])
@validate_api_key
@validate_bearer_token
@log_api_access
def delete_clinic(id):
    clinic = Clinic.query.get(id)

    if not clinic:
        return jsonify({'error': 'Clinic not found'}), 404

    try:
        db.session.delete(clinic)
        db.session.commit()
        return jsonify({'message': 'Clinic deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500