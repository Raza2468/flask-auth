from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from app.extensions import db
from app.utils import AESCipher
import os
from dotenv import load_dotenv
from app.models import Clinic, Patient, LabCaseStatus, BatchCaseStatus, User, PreAuthStatus, AppointmentStatus
from functools import wraps
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token
import base64


load_dotenv()
cipher = AESCipher(key=os.getenv('ENCRYPTION_KEY', 'default_encryption_key'))

status_routes = Blueprint('status_routes', __name__)


@status_routes.route('/lab_case_status', methods=['POST'])
def create_lab_case_status():
    """Create a new lab case status"""
    data = request.get_json()

    # Validate required fields
    if not data.get('status_name') or not data.get('status') or not data.get('user_id'):
        return jsonify({'error': 'status_name, status, and user_id are required'}), 400

    # Create new LabCaseStatus entry
    new_status = LabCaseStatus(
        status_name=data['status_name'],
        status=data['status'],
        user_id=data['user_id']
    )

    db.session.add(new_status)
    db.session.commit()

    return jsonify({'message': 'Lab case status created successfully', 'id': new_status.id}), 201


@status_routes.route('/lab_case_status/<int:status_id>/toggle', methods=['PATCH'])
def toggle_lab_case_status(status_id):
    try:
        # Fetch the LabCaseStatus by ID
        lab_status = LabCaseStatus.query.get(status_id)

        if not lab_status:
            return jsonify({'error': 'Lab case status not found'}), 404

        # Toggle the status between 'active' and 'inactive'
        lab_status.status = 'inactive' if lab_status.status == 'active' else 'active'

        # Commit changes to the database
        db.session.commit()

        return jsonify({
            'message': 'Lab case status updated successfully',
            'status_id': lab_status.id,
            'new_status': lab_status.status
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@status_routes.route('/lab_case_statuses', methods=['GET'])
def get_enabled_lab_case_statuses():
    """Retrieve all enabled lab case statuses with user names"""
    try:
        statuses = db.session.query(
            LabCaseStatus.id,
            LabCaseStatus.status_name,
            LabCaseStatus.status,
            LabCaseStatus.user_id,
            LabCaseStatus.created_at,
            User.first_name,
            User.last_name
        ).outerjoin(User, LabCaseStatus.user_id == User.id).filter(LabCaseStatus.status == 'active').all()

        if not statuses:
            return jsonify({'message': 'No enabled lab case statuses found'}), 404

        return jsonify({
            'enabled_lab_case_statuses': [{
                'id': status.id,
                'status_name': status.status_name,
                'status': status.status,  # 'enabled'
                'user_id': status.user_id,
                'user_name': f"{status.first_name} {status.last_name}".strip(),
                'created_at': status.created_at
            } for status in statuses]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@status_routes.route('/lab_case_status', methods=['GET'])
def get_all_lab_case_statuses():
    """Retrieve all lab case statuses with user names"""
    statuses = db.session.query(
        LabCaseStatus.id,
        LabCaseStatus.status_name,
        LabCaseStatus.status,
        LabCaseStatus.user_id,
        LabCaseStatus.created_at,
        User.first_name,
        User.last_name
    ).outerjoin(User, LabCaseStatus.user_id == User.id).all()

    return jsonify({
        'lab_case_statuses': [{
            'id': status.id,
            'status_name': status.status_name,
            'status': status.status,
            'user_id': status.user_id,
            'user_name': f"{status.first_name} {status.last_name}".strip(),
            'created_at': status.created_at
        } for status in statuses]
    }), 200


@status_routes.route('/lab_case_status/<int:status_id>', methods=['GET'])
def get_lab_case_status(status_id):
    """Retrieve a specific lab case status by ID with user name"""
    status = db.session.query(
        LabCaseStatus.id,
        LabCaseStatus.status_name,
        LabCaseStatus.status,
        LabCaseStatus.user_id,
        LabCaseStatus.created_at,
        User.first_name,
        User.last_name
    ).outerjoin(User, LabCaseStatus.user_id == User.id).filter(LabCaseStatus.id == status_id).first()

    if not status:
        return jsonify({'error': 'Lab case status not found'}), 404

    return jsonify({
        'id': status.id,
        'status_name': status.status_name,
        'status': status.status,
        'user_id': status.user_id,
        'user_name': f"{status.first_name} {status.last_name}".strip(),
        'created_at': status.created_at
    }), 200


#------------------------------Batches Status-------------------------

@status_routes.route('/batch_case_status', methods=['POST'])
def create_batch_case_status():
    """Create a new batch case status"""
    data = request.get_json()

    # Validate input
    required_fields = ['status_name', 'status', 'user_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if the user exists
    user = User.query.get(data['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Create a new BatchCaseStatus
    new_status = BatchCaseStatus(
        status_name=data['status_name'],
        status=data['status'],
        user_id=data['user_id'],
        created_at=datetime.utcnow()
    )

    db.session.add(new_status)
    db.session.commit()

    return jsonify({
        'message': 'Batch case status created successfully',
        'status': {
            'id': new_status.id,
            'status_name': new_status.status_name,
            'status': new_status.status,
            'user_id': new_status.user_id,
            'user_name': f"{user.first_name} {user.last_name}".strip(),
            'created_at': new_status.created_at
        }
    }), 201


@status_routes.route('/batch_case_status', methods=['GET'])
def get_all_batch_case_statuses():
    """Retrieve all batch case statuses with user names"""
    statuses = db.session.query(
        BatchCaseStatus.id,
        BatchCaseStatus.status_name,
        BatchCaseStatus.status,
        BatchCaseStatus.user_id,
        BatchCaseStatus.created_at,
        User.first_name,
        User.last_name
    ).outerjoin(User, BatchCaseStatus.user_id == User.id).all()

    return jsonify({
        'batch_case_statuses': [{
            'id': status.id,
            'status_name': status.status_name,
            'status': status.status,
            'user_id': status.user_id,
            'user_name': f"{status.first_name} {status.last_name}".strip(),
            'created_at': status.created_at
        } for status in statuses]
    }), 200

@status_routes.route('/batch_case_statuses', methods=['GET'])
def get_active_batch_case_statuses():
    """Retrieve all active batch case statuses with user names"""
    try:
        statuses = db.session.query(
            BatchCaseStatus.id,
            BatchCaseStatus.status_name,
            BatchCaseStatus.status,
            BatchCaseStatus.user_id,
            BatchCaseStatus.created_at,
            User.first_name,
            User.last_name
        ).outerjoin(User, BatchCaseStatus.user_id == User.id).filter(BatchCaseStatus.status == 'active').all()

        if not statuses:
            return jsonify({'message': 'No active batch case statuses found'}), 404

        return jsonify({
            'active_batch_case_statuses': [{
                'id': status.id,
                'status_name': status.status_name,
                'status': status.status,  # 'active'
                'user_id': status.user_id,
                'user_name': f"{status.first_name} {status.last_name}".strip(),
                'created_at': status.created_at
            } for status in statuses]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@status_routes.route('/batch_case_status/<int:status_id>/toggle', methods=['PATCH'])
def toggle_batch_case_status(status_id):
    try:
        # Fetch the BatchCaseStatus by ID
        batch_status = BatchCaseStatus.query.get(status_id)

        if not batch_status:
            return jsonify({'error': 'Batch case status not found'}), 404

        # Toggle the status between 'active' and 'inactive'
        batch_status.status = 'inactive' if batch_status.status == 'active' else 'active'

        # Commit changes to the database
        db.session.commit()

        return jsonify({
            'message': 'Batch case status updated successfully',
            'status_id': batch_status.id,
            'new_status': batch_status.status
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@status_routes.route('/batch_case_status/<int:status_id>', methods=['GET'])
def get_batch_case_status(status_id):
    """Retrieve a specific batch case status by ID with user name"""
    status = db.session.query(
        BatchCaseStatus.id,
        BatchCaseStatus.status_name,
        BatchCaseStatus.status,
        BatchCaseStatus.user_id,
        BatchCaseStatus.created_at,
        User.first_name,
        User.last_name
    ).join(User, BatchCaseStatus.user_id == User.id).filter(BatchCaseStatus.id == status_id).first()

    if not status:
        return jsonify({'error': 'Batch case status not found'}), 404

    return jsonify({
        'id': status.id,
        'status_name': status.status_name,
        'status': status.status,
        'user_id': status.user_id,
        'user_name': f"{status.first_name} {status.last_name}".strip(),
        'created_at': status.created_at
    }), 200


#----------------------------------preauthstatus ----------------------
@status_routes.route('/pre_auth_status', methods=['GET'])
def pre_auth_statuses():
    try:
        # Fetch **all** pre-auth statuses (both enabled and disabled)
        statuses = db.session.query(
            PreAuthStatus.id,
            PreAuthStatus.user_id,
            PreAuthStatus.status,
            PreAuthStatus.enabled,
            PreAuthStatus.created_at,
            User.first_name,
            User.last_name
        ).outerjoin(User, PreAuthStatus.user_id == User.id).all()

        print(statuses)

        # If no statuses found
        if not statuses:
            return jsonify({'message': 'No statuses found'}), 404

        # Prepare the response data
        status_data = [{
            'id': status.id,
            'user_id': status.user_id,
            'user_name': f"{status.first_name} {status.last_name}".strip(),
            'status': status.status,
            'enabled': status.enabled,  # Can be True or False
            'created_at': status.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for status in statuses]

        return jsonify({'enabled_statuses': status_data}), 200  # Changed key for clarity

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@status_routes.route('/pre_auth_statuses', methods=['GET'])
def get_enabled_pre_auth_statuses():
    try:
        # Fetch only **enabled** pre-auth statuses
        statuses = (
            db.session.query(PreAuthStatus, User)
            .outerjoin(User, PreAuthStatus.user_id == User.id)
            .filter(PreAuthStatus.enabled == True)  # Keep this for enabled only
            .all()
        )

        # If no enabled statuses found
        if not statuses:
            return jsonify({'message': 'No enabled statuses found'}), 404

        # Prepare the response data
        status_data = [{
            'id': status.id,
            'user_id': status.user_id,
            'user_name': f"{user.first_name} {user.last_name}".strip(),
            'status': status.status,
            'enabled': status.enabled,
            'created_at': status.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for status, user in statuses]

        return jsonify({'enabled_statuses': status_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@status_routes.route('/pre_auth_status', methods=['POST'])
def create_pre_auth_status():
    try:
        # Parse the incoming JSON data
        data = request.get_json()

        # Validate required fields
        if 'user_id' not in data or 'status' not in data:
            return jsonify({'error': 'user_id and status are required fields'}), 400

        # Create a new PreAuthStatus
        pre_auth_status = PreAuthStatus(
            user_id=data['user_id'],
            status=data['status_name'],
            enabled=data.get('enabled', True),  # Default to True if not provided
            created_at=datetime.utcnow()
        )

        # Add to the database
        db.session.add(pre_auth_status)
        db.session.commit()

        return jsonify({'message': 'Pre-auth status created successfully', 'status_id': pre_auth_status.id}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@status_routes.route('/pre_auth_status/<int:status_id>/toggle', methods=['PATCH'])
def toggle_pre_auth_status(status_id):
    try:
        db.session.rollback()  # Clear any previous failed transaction
        pre_auth_status = PreAuthStatus.query.get(status_id)

        if not pre_auth_status:
            return jsonify({'error': 'Pre-auth status not found'}), 404

        # Ensure record wasn't deleted by another request
        db.session.refresh(pre_auth_status)

        # Toggle the enabled status
        pre_auth_status.enabled = not pre_auth_status.enabled

        # Commit changes
        db.session.commit()

        return jsonify({
            'message': 'Pre-auth status updated successfully',
            'status_id': pre_auth_status.id,
            'enabled': pre_auth_status.enabled
        }), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': str(e)}), 500



# 1️⃣ GET all appointment statuses (enabled & disabled)
@status_routes.route('/appointment_statuses', methods=['GET'])
def get_all_appointment_statuses():
    try:
        statuses = db.session.query(
            AppointmentStatus.id,
            AppointmentStatus.user_id,
            AppointmentStatus.status,
            AppointmentStatus.enabled,
            AppointmentStatus.created_at,
            User.first_name,
            User.last_name
        ).outerjoin(User, AppointmentStatus.user_id == User.id).all()

        if not statuses:
            return jsonify({'message': 'No appointment statuses found'}), 404

        status_data = [{
            'id': status.id,
            'user_id': status.user_id,
            'user_name': f"{status.first_name} {status.last_name}".strip(),
            'status': status.status,
            'enabled': status.enabled,
            'created_at': status.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for status in statuses]

        return jsonify({'appointment_statuses': status_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 2️⃣ GET only enabled statuses
@status_routes.route('/appointment_statuses/enabled', methods=['GET'])
def get_enabled_appointment_statuses():
    try:
        statuses = (
            db.session.query(AppointmentStatus, User)
            .outerjoin(User, AppointmentStatus.user_id == User.id)
            .filter(AppointmentStatus.enabled == True)
            .all()
        )

        if not statuses:
            return jsonify({'message': 'No enabled appointment statuses found'}), 404

        status_data = [{
            'id': status.id,
            'user_id': status.user_id,
            'user_name': f"{user.first_name} {user.last_name}".strip(),
            'status': status.status,
            'enabled': status.enabled,
            'created_at': status.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for status, user in statuses]

        return jsonify({'enabled_statuses': status_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 3️⃣ POST to create a new appointment status
@status_routes.route('/appointment_statuses', methods=['POST'])
def create_appointment_status():
    try:
        data = request.get_json()

        if 'user_id' not in data or 'status' not in data:
            return jsonify({'error': 'user_id and status are required fields'}), 400

        appointment_status = AppointmentStatus(
            user_id=data['user_id'],
            status=data['status'],
            enabled=data.get('enabled', True),
            created_at=datetime.utcnow()
        )

        db.session.add(appointment_status)
        db.session.commit()

        return jsonify({
            'message': 'Appointment status created successfully',
            'status_id': appointment_status.id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 4️⃣ PATCH to toggle enabled/disabled
@status_routes.route('/appointment_statuses/<int:status_id>/toggle', methods=['PATCH'])
def toggle_appointment_status(status_id):
    try:
        db.session.rollback()

        status = AppointmentStatus.query.get(status_id)

        if not status:
            return jsonify({'error': 'Appointment status not found'}), 404

        db.session.refresh(status)

        status.enabled = not status.enabled

        db.session.commit()

        return jsonify({
            'message': 'Appointment status updated successfully',
            'status_id': status.id,
            'enabled': status.enabled
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
