from flask import Blueprint, request, jsonify, redirect, current_app,g, session
from datetime import datetime, timedelta
from app.extensions import db
from app.models import Dashboard, User
import jwt
from app.util.decorators import validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard, log_api_access, generate_otp  


# Blueprint Definition
dashboards_bp = Blueprint('dashboards_bp', __name__)

# Secure Token Expiry Time (5 minutes)
TOKEN_EXPIRY_MINUTES = 15

# Function to generate a JWT token for secure redirection
def generate_redirect_token(user_id, dashboard_id):
    expiry = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
    payload = {'user_id': user_id, 'dashboard_id': dashboard_id, 'exp': expiry}
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

# API to generate a secure redirect link
# @dashboards_bp.route('/redirect-dashboard', methods=['GET'])
# def redirect_dashboard():
#     user_id = request.args.get('user_id')
#     dashboard_id = request.args.get('dashboard_id')

#     if not user_id or not dashboard_id:
#         return jsonify({'error': 'User ID and Dashboard ID are required'}), 400

#     # Convert to int for DB lookup
#     user_id = int(user_id)
#     dashboard_id = int(dashboard_id)

#     user = User.query.get(user_id)
#     if not user:
#         return jsonify({'error': 'User not found'}), 404

#     # Ensure user has access to the dashboard (assuming user.dashboard_id is an array)
#     if dashboard_id not in user.dashboard_id:
#         return jsonify({'error': 'Unauthorized access to this dashboard'}), 403

#     dashboard = Dashboard.query.get(dashboard_id)
#     if not dashboard:
#         return jsonify({'error': 'Dashboard not found'}), 404

#     # Generate a secure redirect token
#     token = generate_redirect_token(user_id, dashboard_id)
#     redirect_url = f"{dashboard.dashboard_url}?token={token}"

#     return jsonify({'redirect_url': redirect_url})

# # API to verify token and allow redirection
# # @dashboards_bp.route('/verify-dashboard', methods=['GET'])
# # def verify_dashboard():
#     token = request.args.get('token')

#     if not token:
#         return jsonify({'error': 'Token is required'}), 400

#     try:
#         payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
#         dashboard = Dashboard.query.get(payload['dashboard_id'])

#         if not dashboard:
#             return jsonify({'error': 'Invalid dashboard'}), 404

#         return redirect(dashboard.dashboard_url)

#     except jwt.ExpiredSignatureError:
#         return jsonify({'error': 'Token expired'}), 401
#     except jwt.InvalidTokenError:
#         return jsonify({'error': 'Invalid token'}), 401


import jwt
from flask import Blueprint, request, jsonify, redirect, current_app
from datetime import datetime, timedelta
from app.models import db, User, Dashboard

dashboards_bp = Blueprint('dashboards', __name__)

def generate_redirect_token(user_id, dashboard_id):
    """Generate a secure JWT token for dashboard access."""
    payload = {
        'user_id': user_id,
        'dashboard_id': dashboard_id,
        'exp': datetime.utcnow() + timedelta(hours=2)  # Token expires in 2 hours
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

@dashboards_bp.route('/redirect-dashboard', methods=['GET'])
def redirect_dashboard():
    """Generate a secure redirect link for a user to access a specific dashboard."""
    user_id = request.args.get('user_id')
    dashboard_id = request.args.get('dashboard_id')

    if not user_id or not dashboard_id:
        return jsonify({'error': 'User ID and Dashboard ID are required'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # ✅ Ensure user has access to this dashboard
    if not user.dashboard_id or int(dashboard_id) not in user.dashboard_id:
        return jsonify({'error': 'Unauthorized access to this dashboard'}), 403

    dashboard = Dashboard.query.get(dashboard_id)
    if not dashboard:
        return jsonify({'error': 'Dashboard not found'}), 404

    # ✅ Generate Secure Token
    token = generate_redirect_token(user_id, dashboard_id)
    redirect_url = f"{dashboard.dashboard_url}?token={token}"

    return jsonify({'redirect_url': redirect_url}), 200

@dashboards_bp.route('/verify-dashboard', methods=['GET'])
def verify_dashboard():
    """Verify the token and redirect user to the correct dashboard."""
    token = request.args.get('token')

    if not token:
        return jsonify({'error': 'Token is required'}), 400

    try:
        # ✅ Decode the token
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        dashboard_id = payload['dashboard_id']

        # ✅ Validate user existence
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # ✅ Validate user dashboard access
        if not user.dashboard_id or int(dashboard_id) not in user.dashboard_id:
            return jsonify({'error': 'Unauthorized access to this dashboard'}), 403

        # ✅ Fetch all dashboards for the user in one optimized query
        dashboards = Dashboard.query.filter(Dashboard.id.in_(user.dashboard_id)).all()
        dashboards_data = [
            {
                "id": db.id,
                "name": db.name,
                "dashboard_url": db.dashboard_url,
                "image": db.image,
                "layout": db.layout
            } for db in dashboards
        ]

        # ✅ Check if the requested dashboard exists
        dashboard = next((db for db in dashboards_data if db["id"] == int(dashboard_id)), None)

        if not dashboard:
            return jsonify({'error': 'Invalid dashboard'}), 404

        # ✅ Redirect to dashboard without login
        return redirect(dashboard["dashboard_url"])

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500







# --------------------------------------------

# Utility Function: Standard Error Response
def error_response(message, status_code, details=None):
    """Utility to return a standardized error response."""
    response = {'error': message}
    if details:
        response['details'] = details
    return jsonify(response), status_code


# --------------------------------------------
# CREATE a new Dashboard (POST /dashboard)
# --------------------------------------------
@dashboards_bp.route('/dashboard', methods=['POST'])
@validate_api_key
@log_api_access
def create_dashboard():
    try:
        data = request.get_json() or {}

        # Validate required fields
        if 'name' not in data:
            return error_response("Missing 'name' in request body", 400)

        name = data['name']
        layout = data.get('layout')  # Optional field

        # Create a new Dashboard instance
        new_dashboard = Dashboard(
            name=name,
            layout=layout
        )
        db.session.add(new_dashboard)
        db.session.commit()

        return jsonify({
            "message": "Dashboard created successfully",
            "dashboard_id": new_dashboard.id
        }), 201

    except Exception as e:
        db.session.rollback()
        return error_response("An error occurred while creating the dashboard", 500, str(e))


# --------------------------------------------
# GET ALL Dashboards (GET /dashboard)
# --------------------------------------------
@dashboards_bp.route('/dashboard', methods=['GET'])
@validate_api_key
@validate_bearer_token
# @validate_user_role(['panacea', 'credentialing', 'admin'])
# @validate_user_dashboard(['lab_dashboard', 'panacea', 'credentialing'])
@log_api_access
def get_dashboards():
    try:
           # Debugging: Print user details
        # print("User Details:")
        # print(f"ID: {g.user.id}")
        # print(f"Name: {g.user.name}")  # Adjust field names based on your User model
        # print(f"Email: {g.user.email}")  # Adjust as needed
        # print(f"Role: {g.role.name}")
        # print(f"Dashboard: {g.dashboard.id}")

        # print(f"g.role: {getattr(g.user, 'role', 'Role not set')}")  # Debugging print
        # Retrieve all dashboards from the database
        dashboard_list = Dashboard.query.all()
        if not dashboard_list:
            return jsonify({"message": "No dashboards found"}), 200

        # Prepare response data
        dashboards_data = [
            {
                "id": dashboard.id,
                "name": dashboard.name,
                "layout": dashboard.layout,
                "dashboard_url": dashboard.dashboard_url,
                "created_at": dashboard.created_at.isoformat(),
                "updated_at": dashboard.updated_at.isoformat()
            }
            for dashboard in dashboard_list
        ]

        return jsonify({"dashboards": dashboards_data}), 200

    except Exception as error:
        return error_response("An error occurred while fetching dashboards.", 500, str(error))


# --------------------------------------------
# GET ONE Dashboard by ID (GET /dashboard/<id>)
# --------------------------------------------
@dashboards_bp.route('/dashboard/<int:dashboard_id>', methods=['GET'])
@validate_api_key
@log_api_access
def get_dashboard_by_id(dashboard_id):
    try:
        dashboard = Dashboard.query.get(dashboard_id)
        if not dashboard:
            return error_response(f"Dashboard with ID {dashboard_id} not found", 404)

        dashboard_data = {
            "id": dashboard.id,
            "name": dashboard.name,
            "layout": dashboard.layout,
            "dashboard_url": dashboard.dashboard_url,
            "created_at": dashboard.created_at.isoformat(),
            "updated_at": dashboard.updated_at.isoformat()
        }
        return jsonify({"dashboard": dashboard_data}), 200

    except Exception as e:
        return error_response(f"An error occurred while fetching Dashboard ID {dashboard_id}", 500, str(e))


# --------------------------------------------
# UPDATE a Dashboard by ID (PUT /dashboard/<id>)
# --------------------------------------------
@dashboards_bp.route('/dashboard/<int:dashboard_id>', methods=['PUT'])
@validate_api_key
@log_api_access
def update_dashboard(dashboard_id):
    try:
        dashboard = Dashboard.query.get(dashboard_id)
        if not dashboard:
            return error_response(f"Dashboard with ID {dashboard_id} not found", 404)

        data = request.get_json() or {}

        # Update fields if present
        if 'name' in data:
            dashboard.name = data['name']
        if 'layout' in data:
            dashboard.layout = data['layout']

        dashboard.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify({"message": f"Dashboard {dashboard_id} updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return error_response(f"An error occurred while updating Dashboard ID {dashboard_id}", 500, str(e))


# --------------------------------------------
# DELETE a Dashboard by ID (DELETE /dashboard/<id>)
# --------------------------------------------
@dashboards_bp.route('/dashboard/<int:dashboard_id>', methods=['DELETE'])
@validate_api_key
@log_api_access
def delete_dashboard(dashboard_id):
    try:
        dashboard = Dashboard.query.get(dashboard_id)
        if not dashboard:
            return error_response(f"Dashboard with ID {dashboard_id} not found", 404)

        db.session.delete(dashboard)
        db.session.commit()

        return jsonify({"message": f"Dashboard {dashboard_id} deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return error_response(f"An error occurred while deleting Dashboard ID {dashboard_id}", 500, str(e))


@dashboards_bp.route('/dashboard/check', methods=['POST'])
@log_api_access
def check_dashboard():
    try:
        profile_data = request.json.get('profile')
        if not profile_data:
            return jsonify({'error': 'Profile data not provided in request'}), 400

        # Try to get dashboards as a list first.
        dashboards = profile_data.get('dashboards')
        dashboard_obj = None

        if dashboards and isinstance(dashboards, list):
            # Look for a dashboard with name 'auth'
            for d in dashboards:
                if d.get('name') == 'auth':
                    dashboard_obj = d
                    break
        else:
            # Fallback to a single dashboard object under "dashboard"
            dashboard_obj = profile_data.get('dashboard')
            if dashboard_obj and dashboard_obj.get('name') != 'auth':
                dashboard_obj = None

        if dashboard_obj:
            # Set session variables using the matching dashboard
            session['user_id'] = profile_data.get('id')
            session['first_name'] = profile_data.get('first_name')
            session['last_name'] = profile_data.get('last_name')
            full_name = f"{session.get('first_name', '')} {session.get('last_name', '')}".strip()
            session['full_name'] = full_name    
            session['email'] = profile_data.get('email')
            session['role'] = profile_data.get('role', {}).get('name')
            session['dashboard_id'] = dashboard_obj.get('id')
            session['dashboard_name'] = dashboard_obj.get('name')
            session['dashboard_url'] = dashboard_obj.get('dashboard_url')

            return jsonify({'message': 'Dashboard matched successfully'}), 200
        else:
            return jsonify({'error': 'Dashboard name does not match'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --------------------------------------------






