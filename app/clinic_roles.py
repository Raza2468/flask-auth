from flask import Blueprint, request, jsonify
from app import db
from app.models import ClinicRoles, ApiKey, APILog
from datetime import datetime
from functools import wraps
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard

clinic_roles = Blueprint('clinic_roles', __name__)

# 1. Create a new Clinic Role
@clinic_roles.route('/clinic_roles', methods=['POST'])
@validate_api_key
# @validate_bearer_token
@log_api_access
def create_clinic_role():
    """
    API to create a new clinic role.
    Expects JSON payload with the following keys:
    - clinic_id, role_name, permissions (list of permissions), status (optional, default: 'active')
    """
    data = request.get_json()

    required_fields = ['clinic_id', 'role_name', 'permissions']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Check if the role_name already exists for the same clinic_id
    existing_role = ClinicRoles.query.filter_by(clinic_id=data['clinic_id'], role_name=data['role_name']).first()
    if existing_role:
        return jsonify({'error': 'Role name already exists for this clinic.'}), 400

    try:
        # Create new role
        new_role = ClinicRoles(
            clinic_id=data['clinic_id'],
            role_name=data['role_name'],
            permissions=data['permissions'],
            status=data.get('status', 'active')
        )

        db.session.add(new_role)
        db.session.commit()

        return jsonify({
            'message': 'Clinic role created successfully.',
            'role': new_role.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# 2. Get all Clinic Roles
@clinic_roles.route('/clinic_roles', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def get_clinic_roles():
    roles = ClinicRoles.query.all()

    if roles:
        return jsonify({
            'message': 'Clinic roles fetched successfully.',
            'roles': [role.to_dict() for role in roles]
        }), 200
    else:
        return jsonify({'error': 'No clinic roles found'}), 404


# 3. Get a single Clinic Role by ID
@clinic_roles.route('/clinic_roles/<int:id>', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def get_clinic_role(id):
    role = ClinicRoles.query.get(id)

    if role:
        return jsonify({
            'message': 'Clinic role fetched successfully.',
            'role': role.to_dict()
        }), 200
    else:
        return jsonify({'error': 'Clinic role not found'}), 404


# 4. Update a Clinic Role by ID
@clinic_roles.route('/clinic_roles/<int:id>', methods=['PUT'])
@validate_api_key
@validate_bearer_token
@log_api_access
def update_clinic_role(id):
    data = request.get_json()

    role = ClinicRoles.query.get(id)
    if not role:
        return jsonify({'error': 'Clinic role not found'}), 404

    if 'role_name' in data:
        role.role_name = data['role_name']
    if 'permissions' in data:
        role.permissions = data['permissions']
    if 'status' in data:
        role.status = data['status']

    try:
        db.session.commit()
        return jsonify({
            'message': 'Clinic role updated successfully.',
            'role': role.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# 5. Delete a Clinic Role by ID
@clinic_roles.route('/clinic_roles/<int:id>', methods=['DELETE'])
@validate_api_key
@validate_bearer_token
@log_api_access
def delete_clinic_role(id):
    role = ClinicRoles.query.get(id)
    if not role:
        return jsonify({'error': 'Clinic role not found'}), 404

    try:
        db.session.delete(role)
        db.session.commit()
        return jsonify({'message': 'Clinic role deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
