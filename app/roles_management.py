from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import Role, ApiKey, APILog
from datetime import datetime
from functools import wraps

role = Blueprint('role', __name__)


# Decorator to validate API key in request headers
def require_api_key(f):
    """Decorator to ensure API key is provided and valid."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if not api_key:
            return jsonify({'error': 'API key is required.'}), 401

        if not ApiKey.query.filter_by(api_key=api_key, is_active=True).first():
            return jsonify({'error': 'Invalid or inactive API key.'}), 403

        return f(*args, **kwargs)

    return decorated_function

# Decorator to log API access
def log_api_access(f):
    """Decorator to log API access details."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Retrieve API key and system name
            api_key = request.headers.get('x-api-key', 'Unknown')
            system = ApiKey.query.filter_by(api_key=api_key).first()
            system_name = system.system_name if system else 'Unknown System'

            # Call the actual route function
            response = f(*args, **kwargs)

            # Handle tuple responses (body, status code)
            if isinstance(response, tuple):
                response_body, status_code = response[0], response[1]
            else:
                status_code = response.status_code

            # Log the API access
            log_entry = APILog(
                system_name=system_name,
                endpoint=request.path,
                method=request.method,
                status_code=status_code,
                accessed_at=datetime.utcnow()
            )

            # Save log entry to database
            db.session.add(log_entry)
            db.session.commit()

            return response
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

    return decorated_function

# create role
@role.route('/roles', methods=['POST'])
# @require_api_key
# @log_api_access
def create_role():
    # Extract API key from request headers
    data = request.get_json()
    role_name = data.get('role_name')
    permissions = data.get('permissions')
    status = data.get('status', 'active')  # Default to 'active' if not provided

    if not role_name or not permissions:
        return jsonify({'error': 'Role name and permissions are required.'}), 400

    existing_role = Role.query.filter_by(name=role_name).first()
    if existing_role:
        return jsonify({'error': 'Role with this name already exists.'}), 400

    new_role = Role(name=role_name, permissions=permissions, status=status)
    try:
        db.session.add(new_role)
        db.session.commit()
        return jsonify({'role_id': new_role.id, 'message': 'Role created successfully.'}), 201
    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({'error': str(e)}), 500


# get roles by id
@role.route('/roles/<int:role_id>', methods=['GET'])
@require_api_key
@log_api_access
def get_role(role_id):
    # Extract API key
    api_key = request.headers.get('x-api-key')
    if not api_key:
        return jsonify({'error': 'API key is required.'}), 401

    # Validate the API key
    valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
    if not valid_key:
        return jsonify({'error': 'Invalid or inactive API key.'}), 403

    # Retrieve the role by ID
    role = Role.query.filter_by(id=role_id).first()
    if not role:
        return jsonify({'error': 'Role not found.'}), 404

    return jsonify({
        'role_id': role.id,
        'role_name': role.name,
        'permissions': role.permissions
    }), 200


# update role
@role.route('/roles/<int:role_id>', methods=['PUT'])
@require_api_key
@log_api_access
def update_role(role_id):
    # Extract API key from request headers
    api_key = request.headers.get('x-api-key')
    if not api_key:
        return jsonify({'error': 'API key is required.'}), 401

    # Validate the API key
    valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
    if not valid_key:
        return jsonify({'error': 'Invalid or inactive API key.'}), 403

    data = request.get_json()
    role_name = data.get('role_name')
    permissions = data.get('permissions')
    status = data.get('status')  # status can also be updated

    # Retrieve the role to be updated
    role = Role.query.filter_by(id=role_id).first()
    if not role:
        return jsonify({'error': 'Role not found.'}), 404

    # Check if the role name is being changed and if it's unique
    if role_name and role_name != role.name:
        existing_role = Role.query.filter_by(name=role_name).first()
        if existing_role:
            return jsonify({'error': 'Role name must be unique.'}), 400
        role.name = role_name  # Update role name

    # Update permissions if provided
    if permissions:
        role.permissions = permissions

    # Update status if provided
    if status:
        role.status = status

    # Commit changes to the database
    db.session.commit()

    return jsonify({'message': 'Role updated successfully.'}), 200


# delete role
@role.route('/roles/<int:role_id>', methods=['DELETE'])
@require_api_key
@log_api_access
def delete_role(role_id):
    # Extract API key
    api_key = request.headers.get('x-api-key')
    if not api_key:
        return jsonify({'error': 'API key is required.'}), 401

    # Validate the API key
    valid_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
    if not valid_key:
        return jsonify({'error': 'Invalid or inactive API key.'}), 403

    # Retrieve the role to be deleted
    role = Role.query.filter_by(id=role_id).first()
    if not role:
        return jsonify({'error': 'Role not found.'}), 404

    # Delete the role
    db.session.delete(role)
    db.session.commit()

    return jsonify({'message': 'Role deleted successfully.'}), 200


# get all roles
@role.route('/roles', methods=['GET'])
# @require_api_key
# @log_api_access
def get_all_roles():
    try:
        # Fetch all roles from the database
        roles = Role.query.all()

        # Check if roles exist
        if not roles:
            return jsonify({'message': 'No roles found.'}), 404

        # Prepare the response data
        roles_list = []
        for role in roles:
            roles_list.append({
                'id': role.id,
                'name': role.name,
                'permissions': role.permissions,
                'status': role.status  # Assuming status field is added
            })

        return jsonify({'roles': roles_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500