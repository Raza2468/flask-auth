from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import User, Dashboard, ClinicRoles, ClinicProviders, Clinic, ApiKey, APILog, Role
from datetime import datetime
from functools import wraps
from app.utils import AESCipher
import os
from dotenv import load_dotenv
import pyotp
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard


load_dotenv()
cipher = AESCipher(key=os.getenv('ENCRYPTION_KEY', 'default_encryption_key'))

clinic_providers = Blueprint('clinic_providers', __name__)

# Create a new clinic provider (POST)
@clinic_providers.route('/clinic_providers', methods=['POST'])
@validate_api_key
# @validate_bearer_token
@log_api_access
def create_clinic_provider():
    """Create a new clinic provider."""
    data = request.get_json()

    required_fields = [
        'first_name',
        'last_name',
        'email',
        'phone',
        'designation',
        'clinic_id',
        'tin',
        'state_id',
        'role_id',
        'dashboard_id'
    ]

    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    email = data['email']
    encrypted_email = cipher.encrypt(email)

    if ClinicProviders.query.filter_by(email=encrypted_email).first() or User.query.filter_by(email=encrypted_email).first():
        return jsonify({'error': 'Email already exists in Clinic Providers or Users'}), 400

    role_id = data['role_id']
    role = Role.query.filter_by(id=role_id).first()

    if not role:
        return jsonify({'error': 'Invalid role ID provided'}), 400

    dashboard_id = data.get('dashboard_id')

    if dashboard_id:
        # Validate that the dashboard exists
        dashboard = Dashboard.query.get(dashboard_id)
        if not dashboard:
            return jsonify({'error': f'Dashboard with id={dashboard_id} not found'}), 400

    try:
        new_provider = ClinicProviders(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            phone=data['phone'],
            designation=data['designation'],
            clinic_id=data['clinic_id'],
            tin=data['tin'],
            state_id=data['state_id'],
            npi=data.get('npi')
        )

        db.session.add(new_provider)

        if 'password' in data:
            hashed_password = generate_password_hash(data['password'])
            otp_secret = pyotp.random_base32()
            dashboard_id_int = int(dashboard_id)  # already validated above

            new_user = User(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=email,
                password=hashed_password,
                phone=data['phone'],
                address=data.get('address', ''),
                otp_secret=otp_secret,
                role_id=role_id,
                # Wrap the dashboard id in a list so it fits the ARRAY column:
                dashboard_id=[dashboard_id_int],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(new_user)

        db.session.commit()

        return jsonify({
            'message': 'Clinic provider created successfully.',
            'provider': new_provider.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

 
@clinic_providers.route('/clinic_providers', methods=['GET'])
@validate_api_key
def get_clinic_providers():
    providers = db.session.query(ClinicProviders).all()

    if not providers:
        return jsonify({'error': 'No clinic providers found'}), 404

    provider_list = []
    for provider in providers:
        provider_dict = provider.to_dict()
        provider_dict['provider_name'] = f"{provider_dict['first_name']} {provider_dict['last_name']}"
        provider_dict['status'] = "enable" if provider_dict['status'] == 1 else "disable"
        provider_list.append(provider_dict)

    return jsonify({
        'message': 'Clinic providers fetched successfully',
        'providers': provider_list
    }), 200



# Get a single clinic provider by ID (GET)
@clinic_providers.route('/clinic_providers/<int:id>', methods=['GET'])
@validate_api_key
# @validate_bearer_token
@log_api_access
def get_clinic_provider(id):
    provider = ClinicProviders.query.get(id)
    
    if provider:
        return jsonify({
            'message': 'Clinic provider fetched successfully',
            'provider': provider.to_dict()
        }), 200
    else:
        return jsonify({'error': 'Clinic provider not found'}), 404

# Update a clinic provider (PUT)
@clinic_providers.route('/clinic_providers/<int:provider_id>', methods=['PUT'])
@validate_api_key
@validate_bearer_token
@log_api_access
def update_clinic_provider(provider_id):
    clinic_provider = ClinicProviders.query.get(provider_id)
    
    if not clinic_provider:
        return jsonify({'error': 'Clinic provider not found'}), 404

    request_data = request.get_json()

    # Update fields, encrypt email and phone if provided
    clinic_provider.first_name = cipher.encrypt(request_data.get('first_name', cipher.decrypt(clinic_provider.first_name)))
    clinic_provider.last_name = cipher.encrypt(request_data.get('last_name', cipher.decrypt(clinic_provider.last_name)))
    clinic_provider.email = cipher.encrypt(request_data.get('email', cipher.decrypt(clinic_provider.email)))
    clinic_provider.phone = cipher.encrypt(request_data.get('phone', cipher.decrypt(clinic_provider.phone)))
    clinic_provider.tin = cipher.encrypt(request_data.get('tin', cipher.decrypt(clinic_provider.tin)))
    clinic_provider.state_id = cipher.encrypt(request_data.get('state_id', cipher.decrypt(clinic_provider.state_id)))
    clinic_provider.npi = cipher.encrypt(request_data.get('npi', cipher.decrypt(clinic_provider.npi) if clinic_provider.npi else None))


    try:
        db.session.commit()
        return jsonify({
            'message': 'Clinic provider updated successfully',
            'provider': clinic_provider.to_dict()
        }), 200
    except Exception as error:
        db.session.rollback()
        return jsonify({'error': str(error)}), 500

# Delete a clinic provider (DELETE)
@clinic_providers.route('/clinic_providers/<int:id>', methods=['DELETE'])
@validate_api_key
@validate_bearer_token
@log_api_access
def delete_clinic_provider(id):
    provider = ClinicProviders.query.get(id)
    
    if not provider:
        return jsonify({'error': 'Clinic provider not found'}), 404

    try:
        db.session.delete(provider)
        db.session.commit()
        return jsonify({'message': 'Clinic provider deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Filter clinic providers (GET)
@clinic_providers.route('/clinic_providers/filter', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def filter_clinic_providers():
    """Filter clinic providers based on query parameters."""
    filters = request.args  # Extract query parameters from the request
    
    query = ClinicProviders.query

    # Apply filters if provided
    if 'first_name' in filters:
        query = query.filter(ClinicProviders.first_name.like(f"%{filters['first_name']}%"))
    if 'last_name' in filters:
        query = query.filter(ClinicProviders.last_name.like(f"%{filters['last_name']}%"))
    if 'email' in filters:
        encrypted_email = cipher.encrypt(filters['email'])
        query = query.filter(ClinicProviders.email == encrypted_email)
    if 'phone' in filters:
        encrypted_phone = cipher.encrypt(filters['phone'])
        query = query.filter(ClinicProviders.phone == encrypted_phone)
    if 'clinic_id' in filters:
        query = query.filter(ClinicProviders.clinic_id == filters['clinic_id'])
    if 'role_id' in filters:
        query = query.filter(ClinicProviders.role_id == filters['role_id'])

    # Execute the query
    providers = query.all()

    if providers:
        provider_list = [provider.to_dict() for provider in providers]
        return jsonify({
            'message': 'Filtered clinic providers fetched successfully',
            'providers': provider_list
        }), 200
    else:
        return jsonify({'error': 'No clinic providers found for the given filters'}), 404




@clinic_providers.route('/clinic_providers/<int:provider_id>/toggle', methods=['PATCH'])
def toggle_provider_status(provider_id):
    try:
        db.session.rollback()  # Clear any previous failed transaction
        provider = ClinicProviders.query.get(provider_id)

        if not provider:
            return jsonify({'error': 'Provider not found'}), 404

        # Ensure record wasn't deleted or changed by another request
        db.session.refresh(provider)

        # Toggle the provider status (assuming 1 = active, 0 = inactive)
        provider.status = 0 if provider.status == 1 else 1

        # Commit changes
        db.session.commit()

        return jsonify({
            'message': 'Provider status updated successfully',
            'provider_id': provider.id,
            'status': provider.status  # 1 = enabled, 0 = disabled
        }), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': str(e)}), 500
