from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import ClinicLocation, Clinic, ApiKey, APILog, ClinicRoom  # Assuming ClinicLocation is a model in app.models
from datetime import datetime
from functools import wraps
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard

clinic_locations = Blueprint('clinic_locations', __name__)


# Create a new clinic location
@clinic_locations.route('/clinic_locations', methods=['POST'])
@validate_api_key
@validate_bearer_token
@log_api_access
def create_clinic_location():
   
    data = request.get_json()

    # Check required fields
    required_fields = ['clinic_id', 'location_name', 'address', 'city', 'state', 'postal_code', 'phone', 'email']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f"Missing required fields: {', '.join(missing_fields)}"}), 400

    clinic_id = data['clinic_id']
    location_name = data['location_name']
    address = data['address']
    city = data['city']
    state = data['state']
    postal_code = data['postal_code']
    phone = data['phone']
    email = data['email']

    # Validate email format (if needed)
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400

    # Check if clinic exists
    clinic = Clinic.query.get(clinic_id)
    if not clinic:
        return jsonify({'error': 'Clinic not found'}), 404

    # Create new clinic location
    new_location = ClinicLocation(
        clinic_id=clinic_id,
        location_name=location_name,
        address=address,
        city=city,
        state=state,
        postal_code=postal_code,
        phone=phone,
        email=email
    )

    try:
        db.session.add(new_location)
        db.session.commit()
        return jsonify({'message': 'Clinic location created successfully', 'location_id': new_location.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'An error occurred while creating the clinic location', 'details': str(e)}), 500


# Route to get all clinic locations
@clinic_locations.route('/clinic_locations', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def get_all_clinic_locations():

    clinic_locations = ClinicLocation.query.order_by(ClinicLocation.location_name.asc()).all()

    # Prepare response
    locations_data = []
    for location in clinic_locations:
        locations_data.append({
            'id': location.id,
            'clinic_id': location.clinic_id,
            'location_name': location.location_name,
            'address': location.address,
            'city': location.city,
            'state': location.state,
            'postal_code': location.postal_code,
            'phone': location.phone,
            'email': location.email
        })

    return jsonify({'locations': locations_data}), 200

# Route to get a clinic location by its ID
@clinic_locations.route('/clinic_locations/<int:id>', methods=['GET'])
# @validate_api_key
# @validate_bearer_token
# @log_api_access
def get_clinic_location_by_id(id):
    location = ClinicLocation.query.get(id)
    
    if not location:
        return jsonify({'message': 'Clinic location not found'}), 404
    
    return jsonify({
        'id': location.id,
        'clinic_id': location.clinic_id,
        'location_name': location.location_name,
        'address': location.address,
        'city': location.city,
        'state': location.state,
        'postal_code': location.postal_code,
        'created_at': location.created_at,
        'phone': location.phone,
        'email': location.email
    })


# Route to update a clinic location
@clinic_locations.route('/clinic_locations/<int:location_id>', methods=['PUT'])
@validate_api_key
@validate_bearer_token
@log_api_access
def update_clinic_location(location_id):
    # Get data from the request
    data = request.get_json()
    location_name = data.get('location_name')
    address = data.get('address')
    city = data.get('city')
    state = data.get('state')
    postal_code = data.get('postal_code')
    phone = data.get('phone')
    email = data.get('email')

    # Retrieve the location to be updated
    location = ClinicLocation.query.filter_by(id=location_id).first()
    if not location:
        return jsonify({'error': 'Clinic location not found.'}), 404

    # Update clinic location fields
    if location_name:
        location.location_name = location_name
    if address:
        location.address = address
    if city:
        location.city = city
    if state:
        location.state = state
    if postal_code:
        location.postal_code = postal_code
    if phone:
        location.phone = phone
    if email:
        location.email = email

    # Commit changes
    db.session.commit()

    return jsonify({'message': 'Clinic location updated successfully.'}), 200


# Route to delete a clinic location
@clinic_locations.route('/clinic_locations/<int:location_id>', methods=['DELETE'])
@validate_api_key
@validate_bearer_token
@log_api_access
def delete_clinic_location(location_id):
    # Retrieve the clinic location to be deleted
    location = ClinicLocation.query.filter_by(id=location_id).first()
    if not location:
        return jsonify({'error': 'Clinic location not found.'}), 404

    # Delete the clinic location
    db.session.delete(location)
    db.session.commit()

    return jsonify({'message': 'Clinic location deleted successfully.'}), 200


# --------------------------------ROOMS Management------------------------------

@clinic_locations.route('/locations/<int:location_id>/rooms', methods=['POST'])
def create_room(location_id):
    """Create a new room for a given location."""
    data = request.json

    room_name = data.get('room_name')
    capacity = data.get('capacity', None)
    status = data.get('status', "available")

    if not room_name:
        return jsonify({"error": "Room name is required"}), 400

    # Check if location exists
    location = ClinicLocation.query.get(location_id)
    if not location:
        return jsonify({"error": "Clinic location not found"}), 404

    # Create room
    new_room = ClinicRoom(location_id=location_id, room_name=room_name, capacity=capacity, status=status)
    db.session.add(new_room)
    db.session.commit()

    return jsonify({"message": "Room created successfully", "room_id": new_room.id}), 201

@clinic_locations.route('/locations/<int:location_id>/rooms', methods=['GET'])
def get_rooms(location_id):
    """Retrieve all rooms for a given location."""
    location = ClinicLocation.query.get(location_id)
    if not location:
        return jsonify({"error": "Clinic location not found"}), 404

    rooms = ClinicRoom.query.filter_by(location_id=location_id).all()
    room_list = [
        {
            "id": room.id,
            "room_name": room.room_name,
            "capacity": room.capacity,
            "status": room.status,
            "created_at": room.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for room in rooms
    ]

    return jsonify({"location_id": location_id, "rooms": room_list}), 200



@clinic_locations.route('/rooms/<int:room_id>', methods=['PUT'])
def update_room(room_id):
    """Update room details such as name, capacity, or status."""
    room = ClinicRoom.query.get(room_id)
    if not room:
        return jsonify({"error": "Room not found"}), 404

    data = request.json
    room.room_name = data.get('room_name', room.room_name)
    room.capacity = data.get('capacity', room.capacity)
    room.status = data.get('status', room.status)

    db.session.commit()

    return jsonify({"message": "Room updated successfully"}), 200


@clinic_locations.route('/rooms/<int:room_id>', methods=['DELETE'])
def delete_room(room_id):
    """Delete a room."""
    room = ClinicRoom.query.get(room_id)
    if not room:
        return jsonify({"error": "Room not found"}), 404

    db.session.delete(room)
    db.session.commit()

    return jsonify({"message": "Room deleted successfully"}), 200
