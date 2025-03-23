from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import Clinic, User, ApiKey, APILog, Patient, Insurance
from datetime import datetime
from functools import wraps
from sqlalchemy.exc import IntegrityError

# Blueprint for patient routes
insurance = Blueprint('insurance', __name__)

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


@insurance.route('/insurance', methods=['POST'])
@require_api_key
@log_api_access
def create_insurance():
    data = request.get_json()

    # Ensure all required fields are in the request
    required_fields = ['patient_id', 'clinic_id', 'policy_number', 'provider_name', 'coverage_amount', 'start_date', 'end_date', 'is_active']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    # Get patient and clinic from database
    patient = Patient.query.get(data['patient_id'])
    clinic = Clinic.query.get(data['clinic_id'])

    if not patient or not clinic:
        return jsonify({"error": "Invalid patient or clinic ID"}), 400

    # Ensure 'start_date' and 'end_date' are valid dates
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    # Ensure 'is_active' is a boolean
    if not isinstance(data['is_active'], bool):
        return jsonify({"error": "'is_active' must be a boolean value."}), 400

    # Create new insurance policy
    new_insurance = Insurance(
        policy_number=data['policy_number'],
        provider_name=data['provider_name'],
        coverage_amount=data['coverage_amount'],
        start_date=start_date,
        end_date=end_date,
        is_active=data['is_active'],
        patient_id=patient.id,
        clinic_id=clinic.id,
    )

    try:
        db.session.add(new_insurance)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()  # Rollback the transaction in case of error
        return jsonify({
            "error": "Unique constraint violation",
            "message": f"Policy number {data['policy_number']} already exists."
        }), 409  # Conflict status code

    # Return the newly created insurance policy details along with its ID
    return jsonify({
        "message": "Insurance policy created",
        "insurance": {
            "id": new_insurance.id,
            "policy_number": new_insurance.policy_number,
            "provider_name": new_insurance.provider_name,
            "coverage_amount": new_insurance.coverage_amount,
            "start_date": str(new_insurance.start_date),
            "end_date": str(new_insurance.end_date),
            "is_active": new_insurance.is_active,
            "patient_id": new_insurance.patient_id,
            "clinic_id": new_insurance.clinic_id
        }
    }), 201



@insurance.route('/insurance', methods=['GET'])
@require_api_key
@log_api_access
def get_all_insurances():
    insurances = Insurance.query.all()
    result = []
    for insurance in insurances:
        result.append({
            'id': insurance.id,
            'policy_number': insurance.policy_number,
            'provider_name': insurance.provider_name,
            'coverage_amount': insurance.coverage_amount,
            'start_date': insurance.start_date,
            'end_date': insurance.end_date,
            'is_active': insurance.is_active,
            'patient_id': insurance.patient_id,
            'clinic_id': insurance.clinic_id
        })
    return jsonify(result), 200


@insurance.route('/insurance/<int:id>', methods=['GET'])
@require_api_key
@log_api_access
def get_insurance(id):
    insurance = Insurance.query.get(id)
    if not insurance:
        return jsonify({'message': 'Insurance not found'}), 404
    return jsonify({
        'id': insurance.id,
        'policy_number': insurance.policy_number,
        'provider_name': insurance.provider_name,
        'coverage_amount': insurance.coverage_amount,
        'start_date': insurance.start_date,
        'end_date': insurance.end_date,
        'is_active': insurance.is_active,
        'patient_id': insurance.patient_id,
        'clinic_id': insurance.clinic_id
    }), 200


@insurance.route('/insurance/<int:id>', methods=['PUT'])
@require_api_key
@log_api_access
def update_insurance(id):
    data = request.get_json()
    insurance = Insurance.query.get(id)

    if not insurance:
        return jsonify({'message': 'Insurance not found'}), 404

    try:
        # Update the insurance details with the new data or keep the old ones
        insurance.policy_number = data.get('policy_number', insurance.policy_number)
        insurance.provider_name = data.get('provider_name', insurance.provider_name)
        insurance.coverage_amount = data.get('coverage_amount', insurance.coverage_amount)
        insurance.start_date = datetime.strptime(data.get('start_date', str(insurance.start_date)), '%Y-%m-%d') if data.get('start_date') else insurance.start_date
        insurance.end_date = datetime.strptime(data.get('end_date', str(insurance.end_date)), '%Y-%m-%d') if data.get('end_date') else insurance.end_date
        insurance.is_active = data.get('is_active', insurance.is_active)
        insurance.patient_id = data.get('patient_id', insurance.patient_id)
        insurance.clinic_id = data.get('clinic_id', insurance.clinic_id)

        # Commit the changes to the database
        db.session.commit()

        return jsonify({'message': 'Insurance updated successfully'}), 200

    except IntegrityError as e:
        db.session.rollback()  # Rollback the transaction in case of error

        # Check if the error is related to the unique constraint violation of the policy_number
        if 'UNIQUE constraint failed' in str(e):
            return jsonify({
                'error': 'Policy number must be unique',
                'message': 'The provided policy number already exists.'
            }), 409  # Conflict status code

        return jsonify({'message': 'Failed to update insurance', 'error': str(e)}), 400


@insurance.route('/insurance/<int:id>', methods=['DELETE'])
@require_api_key
@log_api_access
def delete_insurance(id):
    insurance = Insurance.query.get(id)
    if not insurance:
        return jsonify({'message': 'Insurance not found'}), 404

    try:
        db.session.delete(insurance)
        db.session.commit()
        return jsonify({'message': 'Insurance deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete insurance', 'error': str(e)}), 400
