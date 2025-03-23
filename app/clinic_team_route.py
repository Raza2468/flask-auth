from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import Clinic, ClinicRoles,Role, Dashboard, User, ApiKey, APILog, ClinicTeam, StaffLocation, ClinicLocation
from datetime import datetime
from functools import wraps
import uuid
import pyotp
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard
import os
import random
import string
from flask import Blueprint, request, jsonify
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash
from app.models import db, ClinicTeam, User, StaffLocation
import pyotp
import requests


clinic_team = Blueprint('clinic_team', __name__)


@clinic_team.route('/clinic_team', methods=['POST'])
@validate_api_key
# @validate_bearer_token
@log_api_access
def create_clinic_team_member():
    """
    Create a new clinic team member.

    :return: JSON response with message and created team member details
    """
    try:
        data = request.get_json()

        required_fields = [
            'first_name', 'last_name', 'email', 'clinic_role_id', 'designation',
            'password', 'phone', 'address', 'dashboard_id'
        ]

        if not all(field in data for field in required_fields):
            return jsonify({'error': 'All required fields must be provided.'}), 400

        first_name = data['first_name']
        last_name = data['last_name']
        email = data['email']
        clinic_role_id = data['clinic_role_id']
        designation = data['designation']
        password = data['password']
        phone = data['phone']
        address = data['address']
        clinic_id = data.get('clinic_id')
        invited_by_id = data.get('invited_by_id')
        dashboard_id = data.get('dashboard_id')

        invitation_token = str(uuid.uuid4())

        clinic = Clinic.query.filter_by(id=clinic_id).first()
        if not clinic:
            return jsonify({'error': 'Clinic not found.'}), 404

        clinic_role = ClinicRoles.query.filter_by(id=clinic_role_id).first()
        if not clinic_role:
            return jsonify({'error': 'Clinic role not found.'}), 404

        user = User.query.filter_by(email=email).first()

        if user:
            if ClinicTeam.query.filter_by(email=email, clinic_id=clinic_id).first():
                return jsonify({'message': 'User already exists in the clinic team.'}), 200

            team_member = ClinicTeam(
                user_id=user.id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                clinic_role_id=clinic_role_id,
                designation=designation,
                phone=phone,
                address=address,
                clinic_id=clinic_id,
                invited_by_id=invited_by_id,
                status='accepted',
                invitation_token=invitation_token
            )
            db.session.add(team_member)
            db.session.commit()
            return jsonify({'message': 'User has been added to the clinic team.'}), 201

        hashed_password = generate_password_hash(password)
        otp_secret = pyotp.random_base32()

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            phone=phone,
            address=address,
            dashboard_id=dashboard_id,
            clinic_role_id=clinic_role_id,
            otp_secret=otp_secret,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()

        team_member = ClinicTeam(
            user_id=new_user.id,
            first_name=first_name,
            last_name=last_name,
            email=email,
            clinic_role_id=clinic_role_id,
            designation=designation,
            phone=phone,
            address=address,
            clinic_id=clinic_id,
            invited_by_id=invited_by_id,
            status='accepted',
            invitation_token=invitation_token
        )
        db.session.add(team_member)
        db.session.commit()

        send_credentials_email(email, first_name, last_name, password, clinic.clinic_name)
        
        return jsonify({'message': 'New user and clinic team member created successfully.'}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'An unexpected error occurred.', 'details': str(e)}), 500


def send_credentials_email(email, first_name, last_name, password, clinic_name):
    """
    Sends user credentials email using Mailgun.
    """
    login_url = "http://107.21.93.236:3000/"

    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px;">
            <div style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); padding: 20px;">
                <h2 style="color: #3498db; text-align: center;">🔐 Your Login Credentials</h2>
                <hr style="border: none; height: 1px; background-color: #ddd; margin: 20px 0;">
                
                <p style="font-size: 16px; color: #34495e;">Dear {first_name} {last_name},</p>
                <p style="font-size: 16px; color: #34495e;">
                    You have been added to <strong>{clinic_name}</strong> as a team member! Here are your login details:
                </p>
                
                <div style="text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 8px;">
                    <p><b>Email:</b> {email}</p>
                    <p><b>Password:</b> {password}</p>
                </div>

                <p style="text-align: center; font-size: 16px; color: #34495e;">
                    Click the button below to log in and access your account:
                </p>
                <div style="text-align: center; margin: 20px 0;">
                    <a href="{login_url}" style="padding: 12px 24px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 16px; display: inline-block;">Login Now</a>
                </div>

                <p style="font-size: 14px; color: #666666; text-align: center; margin-top: 20px;">
                    If you have any issues, contact support.
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

    data = {
        "from": "support@360dentalbillingsolutions.com",
        "to": email,
        "subject": f"🔐 Your Login Credentials for {clinic_name}",
        "html": html_message
    }

    MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY")
    MAILGUN_API_URL = os.getenv("MAILGUN_API_URL")

    response = requests.post(
        MAILGUN_API_URL,
        auth=("api", MAILGUN_API_KEY),
        data=data
    )

    if response.status_code == 200:
        print(f"✅ Credentials email sent to {email}")
        return True
    else:
        print(f"❌ Failed to send credentials email to {email}. Error: {response.text}")
        return False




@clinic_team.route('/clinic_team', methods=['GET'])
# @validate_api_key
# @validate_bearer_token
# @log_api_access
def get_all_team_members():
    """Get all team members with user details, dashboards, and role information."""
    
    # Create a subquery to unnest the dashboard_id array into rows
    subquery = db.session.query(
        ClinicTeam.id.label("clinic_team_id"),
        ClinicTeam.user_id,
        ClinicTeam.clinic_role_id,
        ClinicTeam.designation,
        ClinicTeam.created_at,
        ClinicTeam.status,  # ✅ Ensure status is in the subquery
        ClinicTeam.updated_at,
        func.unnest(User.dashboard_id).label("dashboard_id")  # Convert array into rows
    ).join(User, ClinicTeam.user_id == User.id).subquery()
    
    # Main query: join with User, Dashboard, Role, and ClinicRoles to fetch descriptive names
    team_members = db.session.query(
        subquery.c.clinic_team_id,
        subquery.c.user_id,
        User.first_name,
        User.last_name,
        User.userStatus,
        User.email,
        User.role_id,                               # User role id
        Role.name.label("user_role"),               # User role name
        subquery.c.clinic_role_id,                  # Clinic role id
        ClinicRoles.role_name.label("clinic_role"), # Clinic role name
        subquery.c.status,  # ✅ Ensure status is in the main query
        subquery.c.designation,
        subquery.c.created_at,
        subquery.c.updated_at,
        Dashboard.id.label("dashboard_id"),
        Dashboard.name.label("dashboard_name")
    ).join(User, subquery.c.user_id == User.id) \
     .outerjoin(Dashboard, subquery.c.dashboard_id == Dashboard.id) \
     .outerjoin(Role, User.role_id == Role.id) \
     .outerjoin(ClinicRoles, subquery.c.clinic_role_id == ClinicRoles.id) \
     .all()
     
    if not team_members:
        return jsonify({'error': 'No team members found.'}), 404
     
    team_data = {}
    for member in team_members:
        if member.clinic_team_id not in team_data:
            team_data[member.clinic_team_id] = {
                'id': member.clinic_team_id,
                'user_id': member.user_id,
                'first_name': member.first_name,
                'last_name': member.last_name,
                'userStatus': member.userStatus,
                'email': member.email,
                'role_id': member.role_id,
                'user_role': member.user_role,
                'clinic_role_id': member.clinic_role_id,
                'clinic_role': member.clinic_role,
                'designation': member.designation,
                'status': member.status if member.status is not None else "Inactive",  # ✅ Handle missing status
                'dashboard_ids': [],
                'dashboard_names': [],
                'created_at': member.created_at,
                'updated_at': member.updated_at
            }
        
        if member.dashboard_id:
            team_data[member.clinic_team_id]['dashboard_ids'].append(member.dashboard_id)
            team_data[member.clinic_team_id]['dashboard_names'].append(member.dashboard_name)
            
    return jsonify({
        'message': 'Team members retrieved successfully.',
        'team_members': list(team_data.values())
    }), 200



@clinic_team.route('/clinic_team/<int:id>', methods=['GET'])
# @validate_api_key
# @validate_bearer_token
# @log_api_access
def get_team_member(id):
    """Get a single team member by ID with user details, dashboards, and role information."""
    
    # Subquery: Unnest the dashboard_id array for the given team member
    subquery = db.session.query(
        ClinicTeam.id.label("clinic_team_id"),
        ClinicTeam.user_id,
        User.role_id,                              # User role id
        ClinicTeam.clinic_role_id,
        ClinicTeam.designation,
        ClinicTeam.created_at,
        ClinicTeam.status,
        ClinicTeam.updated_at,
        func.unnest(User.dashboard_id).label("dashboard_id")  # Convert array into rows
    ).join(User, ClinicTeam.user_id == User.id) \
     .filter(ClinicTeam.id == id) \
     .subquery()
    
    # Main query: Fetch user details along with dashboards
    team_member = db.session.query(
        subquery.c.clinic_team_id,
        subquery.c.user_id,
        User.first_name,
        User.last_name,
        User.userStatus,
        User.email,
        subquery.c.role_id,
        Role.name.label("user_role"),
        subquery.c.clinic_role_id,
        ClinicRoles.role_name.label("clinic_role"),
        subquery.c.designation,
        subquery.c.created_at,
        subquery.c.status,
        subquery.c.updated_at,
        Dashboard.id.label("dashboard_id"),
        Dashboard.name.label("dashboard_name")
    ).join(User, subquery.c.user_id == User.id) \
     .outerjoin(Dashboard, subquery.c.dashboard_id == Dashboard.id) \
     .outerjoin(Role, subquery.c.role_id == Role.id) \
     .outerjoin(ClinicRoles, subquery.c.clinic_role_id == ClinicRoles.id) \
     .all()
    
    if not team_member:
        return jsonify({'error': 'Team member not found.'}), 404

    # ✅ Aggregate data in the same way as `get_all_team_members`
    member_data = {}
    for member in team_member:
        if member.clinic_team_id not in member_data:
            member_data[member.clinic_team_id] = {
                'id': member.clinic_team_id,
                'user_id': member.user_id,
                'first_name': member.first_name,
                'last_name': member.last_name,
                'userStatus': member.userStatus,
                'email': member.email,
                'role_id': member.role_id,
                'user_role': member.user_role,
                'clinic_role_id': member.clinic_role_id,
                'clinic_role': member.clinic_role,
                'designation': member.designation,
                'dashboard_ids': [],
                'dashboard_names': [],
                'created_at': member.created_at,
                'updated_at': member.updated_at
            }
        if member.dashboard_id:
            member_data[member.clinic_team_id]['dashboard_ids'].append(member.dashboard_id)
            member_data[member.clinic_team_id]['dashboard_names'].append(member.dashboard_name)
    
    # ✅ Return aggregated result (ensuring the format is same as get_all)
    return jsonify({
        'message': 'Team member retrieved successfully.',
        'team_member': list(member_data.values())[0]
    }), 200




@clinic_team.route('/clinic_team/preauth', methods=['GET'])
# @validate_api_key
# @validate_bearer_token
# @log_api_access
def get_preauth_team_members():
    """Get all team members whose dashboard is 'preauth'."""

    team_members = db.session.query(
        ClinicTeam.id, 
        ClinicTeam.user_id, 
        User.first_name, 
        User.last_name,
        User.userStatus,
        User.email, 
        ClinicTeam.clinic_role_id, 
        ClinicTeam.designation, 
        ClinicTeam.created_at, 
        ClinicTeam.status, 
        ClinicTeam.updated_at
    ).join(User, ClinicTeam.user_id == User.id)\
    .join(Dashboard, User.dashboard_id == Dashboard.id)\
    .filter(Dashboard.name == "preauth")\
    .all()

    if not team_members:
        return jsonify({'error': 'No team members found for preauth dashboard.'}), 404

    return jsonify({
        'message': 'Preauth team members retrieved successfully.',
        'team_members': [{
            'id': member.id,
            'user_id': member.user_id,
            'first_name': member.first_name,
            'last_name': member.last_name,
            'status': member.status,
            'email': member.email,
            'clinic_role_id': member.clinic_role_id,
            'designation': member.designation,
            'created_at': member.created_at,
            'updated_at': member.updated_at
        } for member in team_members]
    }), 200


@clinic_team.route('/clinic_team/<int:id>', methods=['PUT'])
# @validate_api_key
# @validate_bearer_token
# @log_api_access
def update_team_member(id):
    """Update a team member's details."""
    data = request.get_json()

    team_member = ClinicTeam.query.get(id)
    if not team_member:
        return jsonify({'error': 'Team member not found.'}), 404

    user = User.query.get(team_member.user_id)
    if not user:
        return jsonify({'error': 'User not found for this team member.'}), 404

    # Update ClinicTeam fields
    if 'clinic_role_id' in data:
        clinic_role = ClinicRoles.query.get(data['clinic_role_id'])
        if not clinic_role:
            return jsonify({'error': 'Invalid clinic role ID.'}), 404
        team_member.clinic_role_id = data['clinic_role_id']

    if 'designation' in data:
        team_member.designation = data['designation']
    if 'status' in data:
        team_member.status = data['status']

    # Update User fields
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'userStatus' in data:
        user.userStatus = data['userStatus']
    if 'clinic_role_id' in data:
        user.clinic_role_id = data['clinic_role_id']

    try:
        db.session.commit()

        # 🟢 Fetch updated data (LIKE GET BY ID API)
        subquery = db.session.query(
            ClinicTeam.id.label("clinic_team_id"),
            ClinicTeam.user_id,
            User.role_id,
            ClinicTeam.clinic_role_id,
            ClinicTeam.designation,
            ClinicTeam.created_at,
            ClinicTeam.status,
            ClinicTeam.updated_at,
            func.unnest(User.dashboard_id).label("dashboard_id")
        ).join(User, ClinicTeam.user_id == User.id) \
         .filter(ClinicTeam.id == id) \
         .subquery()

        updated_member = db.session.query(
            subquery.c.clinic_team_id,
            subquery.c.user_id,
            User.first_name,
            User.last_name,
            User.userStatus,
            User.email,
            User.role_id,
            Role.name.label("user_role"),
            subquery.c.clinic_role_id,
            ClinicRoles.role_name.label("clinic_role"),
            subquery.c.designation,
            subquery.c.created_at,
            subquery.c.status,
            subquery.c.updated_at,
            Dashboard.id.label("dashboard_id"),
            Dashboard.name.label("dashboard_name")
        ).join(User, subquery.c.user_id == User.id) \
         .outerjoin(Dashboard, subquery.c.dashboard_id == Dashboard.id) \
         .outerjoin(Role, subquery.c.role_id == Role.id) \
         .outerjoin(ClinicRoles, subquery.c.clinic_role_id == ClinicRoles.id) \
         .all()

        if not updated_member:
            return jsonify({'error': 'Team member not found after update.'}), 404


        # Aggregate dashboard details
        member_data = {}
        for member in updated_member:
            if member.clinic_team_id not in member_data:
                member_data[member.clinic_team_id] = {
                    'id': member.clinic_team_id,
                    'user_id': member.user_id,
                    'first_name': member.first_name,
                    'last_name': member.last_name,
                    'userStatus': member.userStatus,
                    'email': member.email,
                    'role_id': member.role_id,
                    'user_role': member.user_role or "N/A",  # Handle None
                    'clinic_role_id': member.clinic_role_id,
                    'clinic_role': member.clinic_role or "N/A",  # Handle None
                    'designation': member.designation,
                    'dashboard_ids': [],
                    'dashboard_names': [],
                    'created_at': member.created_at,
                    'updated_at': member.updated_at
                }
            if member.dashboard_id:
                member_data[member.clinic_team_id]['dashboard_ids'].append(member.dashboard_id)
                member_data[member.clinic_team_id]['dashboard_names'].append(member.dashboard_name)

        team_member_data = list(member_data.values())[0]

        return jsonify({
            'message': 'Team member updated successfully.',
            'team_member': team_member_data
        }), 200

    except Exception as e:
        db.session.rollback()
        print("Error:", str(e))  # 🟢 Debugging: Print error
        return jsonify({'error': str(e)}), 500


@clinic_team.route('/clinic_team/<int:id>', methods=['DELETE'])
@validate_api_key
@validate_bearer_token
@log_api_access
def delete_team_member(id):
    """Delete a team member."""
    team_member = ClinicTeam.query.get(id)
    if not team_member:
        return jsonify({'error': 'Team member not found.'}), 404

    try:
        db.session.delete(team_member)
        db.session.commit()
        return jsonify({'message': 'Team member deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@clinic_team.route("/clinic_team/assign-location", methods=["POST"])
@validate_api_key
# @validate_bearer_token
@log_api_access
def assign_location():
    try:
        data = request.json

        # Validate required fields
        required_fields = ["clinic_id", "staff_id", "location_ids"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Extract data from request
        clinic_id = data["clinic_id"]
        staff_id = data["staff_id"]
        location_ids = data["location_ids"]  # Expecting a list of location IDs

        if not isinstance(location_ids, list):
            return jsonify({"error": "location_ids should be a list of location IDs"}), 400

        # Ensure that we don't assign a location that's already assigned
        existing_assignments = db.session.query(StaffLocation).filter(
            StaffLocation.clinic_id == clinic_id,
            StaffLocation.staff_id == staff_id,
            StaffLocation.location_id.in_(location_ids)
        ).all()

        # If any locations are already assigned, we return a message with those
        already_assigned_locations = [assignment.location_id for assignment in existing_assignments]
        if already_assigned_locations:
            return jsonify({
                "error": "The following locations are already assigned to the staff",
                "locations": already_assigned_locations
            }), 400

        # Create new records for each location
        new_assignments = [
            StaffLocation(
                clinic_id=clinic_id,
                location_id=location_id,
                staff_id=staff_id,
                created_at=datetime.utcnow()
            ) for location_id in location_ids
        ]

        db.session.add_all(new_assignments)
        db.session.commit()

        return jsonify({
            "message": "Locations assigned to staff successfully",
            "assigned_locations": [location_id for location_id in location_ids]
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500





@clinic_team.route("/clinic_team/staff/locations/<int:staff_id>", methods=["GET"])
# @validate_api_key
# @validate_bearer_token
@log_api_access
def get_staff_locations(staff_id):
    try:
        # Query staff locations and join with clinic_locations to get location_name
        results = (
            db.session.query(
                StaffLocation.id,
                StaffLocation.clinic_id,
                StaffLocation.location_id,
                StaffLocation.staff_id,
                # StaffLocation.clinic_team_id,
                StaffLocation.created_at,
                ClinicLocation.location_name
            )
            .join(ClinicLocation, StaffLocation.location_id == ClinicLocation.id)
            .filter(StaffLocation.staff_id == staff_id)
            .all()
        )

        if not results:
            return jsonify({"message": "No locations found for this staff member"}), 404

        # Convert query results into a list of dictionaries
        locations = [
            {
                "id": row.id,
                "clinic_id": row.clinic_id,
                "location_id": row.location_id,
                "staff_id": row.staff_id,
                # "clinic_team_id": row.clinic_team_id,
                "created_at": row.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "location_name": row.location_name
            }
            for row in results
        ]

        return jsonify({"staff_locations": locations}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@clinic_team.route('/staff_locations/get_by_staff/<string:staff_id>', methods=['GET'])
# @require_api_key
# @validate_token
# @log_api_access
def get_staff_location_name(staff_id):
    try:
        # Fetch staff locations along with location names from the database
        staff_locations = db.session.query(
            StaffLocation.id,
            StaffLocation.staff_id,
            StaffLocation.location_id,
            ClinicLocation.location_name,  # Fetch location name directly
            StaffLocation.created_at
        ).join(ClinicLocation, StaffLocation.location_id == ClinicLocation.id, isouter=True) \
        .filter(StaffLocation.staff_id == staff_id).all()

        if not staff_locations:
            return jsonify({'message': 'No locations found for this staff ID'}), 404

        # Prepare response data
        staff_location_list = [
            {
                'id': loc.id,
                'staff_id': loc.staff_id,
                'location_id': loc.location_id,
                'location_name': loc.location_name if loc.location_name else 'Unknown',
                'created_at': loc.created_at.strftime('%Y-%m-%d %H:%M:%S') if loc.created_at else None
            }
            for loc in staff_locations
        ]

        return jsonify({'locations': staff_location_list}), 200

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({'error': str(e)}), 500



@clinic_team.route('/staff_locations/get_by_location/<string:location_id>', methods=['GET'])
# @require_api_key
# @validate_token
# @log_api_access
def get_staff_by_location(location_id):
    try:
        # Fetch staff members assigned to the given location ID
        staff_members = db.session.query(
            StaffLocation.id,
            StaffLocation.staff_id,
            StaffLocation.location_id,
            User.first_name,
            User.last_name,
            User.email,
            User.phone,
            StaffLocation.created_at
        ).join(User, StaffLocation.staff_id == User.id, isouter=True) \
        .filter(StaffLocation.location_id == location_id).all()

        if not staff_members:
            return jsonify({'message': 'No staff members found for this location ID'}), 404

        # Prepare response data
        staff_list = [
            {
                'id': staff.id,
                'email': staff.email,
                'phone': staff.phone,
                'staff_id': staff.staff_id,
                'location_id': staff.location_id,
                'staff_name': f"{staff.first_name} {staff.last_name}".strip() if staff.first_name else 'Unknown',
                'created_at': staff.created_at.strftime('%Y-%m-%d %H:%M:%S') if staff.created_at else None
            }
            for staff in staff_members
        ]

        return jsonify({'staff_members': staff_list}), 200

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({'error': str(e)}), 500



@clinic_team.route('/staff_locations/delete/<int:staff_id>/<string:location_id>', methods=['DELETE'])
# @require_api_key
# @validate_token
# @log_api_access
def delete_staff_from_location(staff_id, location_id):
    try:
        # Find the staff location entry
        staff_location = StaffLocation.query.filter_by(staff_id=staff_id, location_id=location_id).first()

        if not staff_location:
            return jsonify({'error': 'Staff member not found at this location'}), 404

        # Delete the staff location entry
        db.session.delete(staff_location)
        db.session.commit()

        return jsonify({'message': 'Staff member removed from location successfully'}), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        print(f"Unexpected error: {str(e)}")
        return jsonify({'error': str(e)}), 500



# clinic_team = Blueprint("clinic_team", __name__)

@clinic_team.route("/team/send_invitation", methods=["POST"])
def send_invitation():
    try:
        data = request.get_json()

        # Extract required fields from request
        name = data.get("name")
        email = data.get("email")
        role = data.get("role")
        designation = data.get("designation")
        selected_locations = data.get("locations")
        invited_by_id = data.get("user_id")
        clinic_id = data.get("clinic_id")

        if not name or not email or not role or not designation or not selected_locations or not invited_by_id or not clinic_id:
            return jsonify({"error": "Missing required fields"}), 400

        # Check if invitation is already sent or user is registered
        invite_sent = ClinicTeam.query.filter_by(email=email).first()
        user_registered = User.query.filter_by(email=email).first()

        if not invite_sent and not user_registered:
            # Generate invitation token
            invitation_token = "".join(random.choices(string.ascii_letters + string.digits, k=64))

            # Get clinic name
            clinic = Clinic.query.filter_by(id=clinic_id).first()
            clinic_name = clinic.clinic_name if clinic else "Unknown Clinic"

            # Store invitation in the database
            new_invite = ClinicTeam(
                user_id=None,  # New invite, no user assigned yet
                email=email,
                invitation_token=invitation_token,
                status="pending",
                clinic_id=clinic_id,
                designation=designation,
                clinic_role_id=role,
                invited_by_id=invited_by_id
            )
            db.session.add(new_invite)
            db.session.commit()

            # Assign staff to selected locations
            for location_id in selected_locations:
                new_staff_location = StaffLocation(
                    clinic_id=clinic_id, location_id=location_id, staff_id=new_invite.id
                )
                db.session.add(new_staff_location)

            db.session.commit()

            # Send Email Invitation
            send_invitation_email(email, name, clinic_name, invitation_token)

            return jsonify({"message": "Invitation sent successfully!"}), 200

        elif not invite_sent and user_registered:
            # Add registered user to clinic team
            user = User.query.filter_by(email=email).first()
            user_id = user.id

            new_team_member = ClinicTeam(
                user_id=user_id,
                email=email,
                clinic_role_id=role,
                designation=designation,
                clinic_id=clinic_id,
                invited_by_id=invited_by_id,
                status="accepted",
                invitation_token=None
            )
            db.session.add(new_team_member)
            db.session.commit()

            return jsonify({"message": "User added to the clinic team successfully."}), 200

        else:
            return jsonify({"error": "User is already invited or added to the clinic team."}), 400

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while sending the invitation", "details": str(e)}), 500


# ========================== EMAIL SENDING FUNCTION ==========================

def send_invitation_email(email, name, clinic_name, invitation_token):
    """
    Function to send an invitation email using Mailgun.
    """
    invitation_link = f"http://localhost:3000/auth/accept_invitation?token={invitation_token}?email={email}"

    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px;">
            <div style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); padding: 20px;">
                <h2 style="color: #2c3e50; text-align: center;">🎉 Welcome to {clinic_name}!</h2>
                <hr style="border: none; height: 1px; background-color: #ddd; margin: 20px 0;">
                
                <div style="text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 8px;">
                    <p style="color: #7f8c8d; font-size: 16px; margin-top: 10px;">
                        Dear <strong>{name}</strong>,
                    </p>
                    <p style="color: #34495e; font-size: 16px;">
                        You have been invited to join <strong>{clinic_name}</strong> as a team member!
                    </p>
                    <p style="color: #7f8c8d; font-size: 16px;">
                        Click the button below to accept your invitation and set up your account:
                    </p>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="{invitation_link}" style="padding: 12px 24px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 16px; display: inline-block;">Accept Invitation</a>
                    </div>
                </div>
                
                <p style="font-size: 14px; color: #666666; text-align: center; margin-top: 20px;">
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

    data = {
        "from": "support@360dentalbillingsolutions.com",
        "to": email,
        "subject": f"🎉 Invitation to Join {clinic_name}",
        "html": html_message
    }

    MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY")
    MAILGUN_API_URL = os.getenv("MAILGUN_API_URL")

    response = requests.post(
        MAILGUN_API_URL,
        auth=("api", MAILGUN_API_KEY),
        data=data
    )

    if response.status_code == 200:
        print(f"✅ Invitation email sent to {email}")
        return True
    else:
        print(f"❌ Failed to send invitation email to {email}. Error: {response.text}")
        return False


@clinic_team.route("/team/register", methods=["POST"])
def register_team_member():
    try:
        data = request.get_json()

        # Extract form data
        full_name = data.get("name")
        email = data.get("email")
        address = data.get("address")
        phone = data.get("phone")
        password = data.get("password")
        confirm_password = data.get("con_password")
        invitation_token = data.get("invitation_token")

        # Validate required fields
        if not all([full_name, email, address, phone, password, confirm_password, invitation_token]):
            return jsonify({"error": "Missing required fields"}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        # Check if invitation exists and is valid
        invitation = ClinicTeam.query.filter_by(invitation_token=invitation_token, email=email).first()
        if not invitation:
            return jsonify({"error": "Invalid or expired invitation token"}), 404

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "User already registered"}), 400

        # Generate a secure password hash
        hashed_password = generate_password_hash(password)

        # Generate a secure OTP secret
        otp_secret = pyotp.random_base32()

        # Split name into first and last name
        first_name, last_name = (full_name.split(" ", 1) + [""])[:2]

        # Create new user
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            address=address,
            password=hashed_password,
            otp_secret=otp_secret,  # ✅ Ensuring the column is not NULL
            userStatus="active",
            is_active=True
        )
        db.session.add(new_user)
        db.session.commit()

        # Link the new user to ClinicTeam
        invitation.user_id = new_user.id
        invitation.status = "accepted"
        invitation.invitation_token = None  # Remove token after accepting
        db.session.commit()

        # Assign staff member to their locations
        staff_locations = StaffLocation.query.filter_by(staff_id=invitation.id).all()
        for location in staff_locations:
            location.staff_id = new_user.id

        db.session.commit()

        return jsonify({
            "message": "User registered and invitation accepted successfully",
            "user_id": new_user.id,
            "email": new_user.email,
            "clinic_team_status": "accepted"
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while registering the user", "details": str(e)}), 500




@clinic_team.route("/team/resend_invitation/<int:team_member_id>", methods=["POST"])
def resend_invitation(team_member_id):
    try:
        # ✅ Fetch the existing team member by ID
        team_member = ClinicTeam.query.filter_by(id=team_member_id).first()

        if not team_member:
            return jsonify({"error": "Team member not found"}), 404

        # ✅ Generate a new invitation token
        invitation_token = "".join(random.choices(string.ascii_letters + string.digits, k=64))
        team_member.invitation_token = invitation_token  # Update token
        db.session.commit()

        # ✅ Get clinic details
        clinic = Clinic.query.filter_by(id=team_member.clinic_id).first()
        clinic_name = clinic.clinic_name if clinic else "Unknown Clinic"

        # ✅ Send email invitation
        send_invitation_email(team_member.email, team_member.email.split('@')[0], clinic_name, invitation_token)

        return jsonify({"message": "Invitation resent successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to resend invitation", "details": str(e)}), 500