from flask import Blueprint, request, jsonify, session, Response
from flask_login import login_required, current_user, login_user, logout_user
import pyotp
import pyqrcode
import io
from app.models import User, Role, Dashboard, ClinicTeam, Clinic, ClinicRoles
from werkzeug.security import check_password_hash
import logging
from datetime import datetime, timedelta
import jwt
from flask import current_app
import base64
from app import db
from app.util.decorators import validate_api_key, validate_bearer_token, validate_user_role, validate_user_dashboard, log_api_access


# Setup logging
logging.basicConfig(level=logging.INFO)

two_factor = Blueprint('two_factor', __name__)

# @two_factor.route('/login', methods=['POST'])
# @validate_api_key
# @log_api_access
# def login():
#     try:
#         data = request.json
#         email = data.get('email')
#         password = data.get('password')

#         if not email or not password:
#             return jsonify({'error': 'Email and password are required'}), 400

#         # Authenticate user
#         user = User.query.filter_by(email=email).first()
#         if user and check_password_hash(user.password, password):
#             if current_user.is_authenticated:
#                 logout_user()

#             login_user(user)

#             # Check if the user already has a 2FA secret
#             if not user.otp_secret:
#                 user.otp_secret = pyotp.random_base32()
#                 db.session.commit()

#             # Generate a temporary token for 2FA verification
#             temp_token = jwt.encode(
#                 {
#                     'id': user.id,
#                     'iat': datetime.utcnow(),
#                     'exp': datetime.utcnow() + timedelta(minutes=10),
#                 },
#                 current_app.config['SECRET_KEY'],
#                 algorithm="HS256"
#             )

#             # Generate the QR code for the user
#             totp = pyotp.TOTP(user.otp_secret)
#             otp_url = totp.provisioning_uri(
#                 name=f"{user.first_name} {user.last_name} ({user.email})",
#                 issuer_name="FlaskApp"
#             )
#             qr_code = pyqrcode.create(otp_url)

#             # Save the QR code as PNG in memory
#             stream = io.BytesIO()
#             qr_code.png(stream, scale=5)
#             qr_code_base64 = base64.b64encode(stream.getvalue()).decode('utf-8')

#             return jsonify({
#                 'qr_code': qr_code_base64,
#                 'temp_token': temp_token
#             }), 200

#         return jsonify({'error': 'Invalid email or password'}), 401

#     except Exception as e:
#         logging.error(f"Error during login: {str(e)}")
#         return jsonify({'error': 'An unexpected error occurred during login'}), 500

   
# @two_factor.route('/verify_2fa', methods=['POST'])
# @validate_api_key
# @log_api_access
# def verify_2fa():
    # try:
    #     data = request.json
    #     token = data.get('token')
    #     temp_token = data.get('temp_token')

    #     if not token or not temp_token:
    #         return jsonify({'error': 'Token and temporary token are required'}), 400

    #     try:
    #         temp_data = jwt.decode(
    #             temp_token,
    #             current_app.config['SECRET_KEY'],
    #             algorithms=["HS256"]
    #         )
    #     except jwt.ExpiredSignatureError:
    #         return jsonify({'error': 'Temporary token has expired'}), 401
    #     except jwt.InvalidTokenError:
    #         return jsonify({'error': 'Invalid temporary token'}), 401

    #     user_id = temp_data['id']
    #     user = User.query.get(user_id)

    #     if not user or not user.otp_secret:
    #         return jsonify({'error': '2FA secret not found for the user'}), 404

    #     totp = pyotp.TOTP(user.otp_secret)
    #     if not totp.verify(token, valid_window=1):
    #         return jsonify({'error': 'Invalid 2FA token'}), 401

    #     # Fetch role and dashboard information
    #     user_role = Role.query.filter_by(id=user.role_id).first()
    #     user_dashboard = Dashboard.query.filter_by(id=user.dashboard_id).first()

    #     # Check if the user has a clinic_role_id and fetch clinic_id from ClinicTeam
    #     clinic_id = None
    #     if user.clinic_role_id:
    #         clinic_team = ClinicTeam.query.filter_by(user_id=user.id).first()
    #         if clinic_team:
    #             clinic_id = clinic_team.clinic_id

    #     # Prepare the final token payload
    #     token_payload = {
    #         'id': user.id,
    #         'name': f"{user.first_name} {user.last_name}",
    #         'email': user.email,
    #         'role': {
    #             'id': user_role.id if user_role else None,
    #             'name': user_role.name if user_role else 'user'
    #         },
    #         'dashboard': {
    #             'id': user_dashboard.id if user_dashboard else None,
    #             'name': user_dashboard.name if user_dashboard else 'default_dashboard'
    #         },
    #         'clinic_id': clinic_id,  # Include clinic_id in the token payload
    #         'exp': datetime.utcnow() + timedelta(hours=5),
    #     }

    #     # Generate the final JWT token
    #     final_token = jwt.encode(
    #         token_payload,
    #         current_app.config['SECRET_KEY'],
    #         algorithm="HS256"
    #     )

    #     return jsonify({
    #         'message': '2FA verification successful',
    #         'token': final_token
    #     }), 200

    # except Exception as e:
    #     logging.error(f"Error during 2FA verification: {str(e)}", exc_info=True)
    #     return jsonify({'error': 'An unexpected error occurred during 2FA verification'}), 500
    




    # -----------------------------------------





@two_factor.route('/login', methods=['POST'])
@validate_api_key
@log_api_access
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if current_user.is_authenticated:
                logout_user()
            login_user(user)

            qr_code_base64 = None

            # If the user hasn't scanned the QR code yet (first_login == 1),
            # generate a QR code along with OTP secret if needed.
            if user.first_login == 0:
                # If OTP secret is not set (new user), generate one.
                if not user.otp_secret:
                    user.otp_secret = pyotp.random_base32()
                    db.session.commit()

                totp = pyotp.TOTP(user.otp_secret)
                otp_url = totp.provisioning_uri(
                    name=f"{user.first_name} {user.last_name} ({user.email})",
                    issuer_name="FlaskApp"
                )
                qr_code = pyqrcode.create(otp_url)

                # Save the QR code as a PNG image in memory and encode it in base64
                stream = io.BytesIO()
                qr_code.png(stream, scale=5)
                qr_code_base64 = base64.b64encode(stream.getvalue()).decode('utf-8')

            # Generate a temporary token (valid for 10 minutes) for 2FA verification
            temp_token = jwt.encode(
                {
                    'id': user.id,
                    'iat': datetime.utcnow(),
                    'exp': datetime.utcnow() + timedelta(minutes=10),
                },
                current_app.config['SECRET_KEY'],
                algorithm="HS256"
            )

            response_payload = {'temp_token': temp_token}

            # Include the QR code only if the user hasn't scanned it yet.
            if qr_code_base64:
                response_payload['qr_code'] = qr_code_base64

            return jsonify(response_payload), 200

        return jsonify({'error': 'Invalid email or password'}), 401

    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred during login'}), 500


@two_factor.route('/verify_2fa', methods=['POST'])
@validate_api_key
def verify_2fa():
    try:
        data = request.json
        token = data.get('token')
        temp_token = data.get('temp_token')

        if not token or not temp_token:
            return jsonify({'error': 'Token and temporary token are required'}), 400

        # Decode the temporary token
        try:
            temp_data = jwt.decode(
                temp_token,
                current_app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Temporary token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid temporary token'}), 401

        user_id = temp_data['id']
        user = User.query.get(user_id)

        if not user or not user.otp_secret:
            return jsonify({'error': '2FA secret not found for the user'}), 404

        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(token, valid_window=1):
            return jsonify({'error': 'Invalid 2FA token'}), 401

        # Mark that the user has scanned the QR code by updating the first_login flag.
        # (Assuming first_login==0 means not yet verified; set it to 1 after successful verification)
        if user.first_login == 0:
            user.first_login = 1
            db.session.commit()

        # Fetch additional user details for the final token
        user_role = Role.query.filter_by(id=user.role_id).first()

        # If using an array for dashboards, fetch all assigned dashboards.
        dashboards_data = []
        if user.dashboard_id:
            # Convert the dashboard_id to a plain list (if not already)
            dashboard_id_list = list(user.dashboard_id)
            dashboards = Dashboard.query.filter(Dashboard.id.in_(dashboard_id_list)).all()
            dashboards_data = [{
                "id": dash.id,
                "name": dash.name,
                "image": dash.image,
                "dashboard_url": dash.dashboard_url,
                "layout": dash.layout,
              } for dash in dashboards]

        # Fetch clinic info if available
        clinic_id = None
        if user.clinic_role_id:
            clinic_team = ClinicTeam.query.filter_by(user_id=user.id).first()
            if clinic_team:
                clinic_id = clinic_team.clinic_id

        # Prepare the final token payload (valid for 5 hours)
        token_payload = {
            'id': user.id,
            'name': f"{user.first_name} {user.last_name}",
            'email': user.email,
            'role': {
                'id': user_role.id if user_role else None,
                'name': user_role.name if user_role else 'user'
            },
            # Include a list of dashboards (which can be empty, or have one or more entries)
            'dashboards': dashboards_data,
            'clinic_id': clinic_id,
            'exp': datetime.utcnow() + timedelta(hours=100),
        }

        final_token = jwt.encode(
            token_payload,
            current_app.config['SECRET_KEY'],
            algorithm="HS256"
        )

        return jsonify({
            'message': '2FA verification successful',
            'token': final_token
        }), 200

    except Exception as e:
        logging.error(f"Error during 2FA verification: {str(e)}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred during 2FA verification'}), 500


@two_factor.route('/auth_profile', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def get_auth_profile():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token is required'}), 401

        token = auth_header.split(' ')[1]
        try:
            decoded_token = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired. Please log in again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token. Please log in again.'}), 401

        user = User.query.filter_by(id=decoded_token['id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Fetch clinic_id and user_role from ClinicTeam (if available)
        clinic_id = getattr(user, 'clinic_id', None)
        user_role = "Unknown"
        clinic_team = ClinicTeam.query.filter_by(user_id=user.id).first()
        if clinic_team:
            if clinic_team.clinic_id:
                clinic_id = clinic_team.clinic_id
            clinic_role = ClinicRoles.query.filter_by(id=clinic_team.clinic_role_id).first()
            if clinic_role:
                user_role = clinic_role.role_name

        # Fetch dashboard(s) assigned to the user
        dashboards_list = []
        if user.dashboard_id:
            # If user.dashboard_id is a list, use the IN operator; else, treat it as a single value.
            if isinstance(user.dashboard_id, list):
                dashboards = Dashboard.query.filter(Dashboard.id.in_(user.dashboard_id)).all()
            else:
                dashboard = Dashboard.query.filter_by(id=user.dashboard_id).first()
                dashboards = [dashboard] if dashboard else []
            dashboards_list = [{
                "id": dash.id,
                "name": dash.name,
                "image": dash.image,
                "dashboard_url": dash.dashboard_url,
                "layout": dash.layout,
            } for dash in dashboards if dash is not None]

        profile_data = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': decoded_token.get('role', 'user'),
            'dashboards': dashboards_list,  # List of dashboard(s)
            'clinic_id': clinic_id,
            'user_role': user_role
        }

        return jsonify({'message': 'Profile retrieved successfully', 'profile': profile_data}), 200

    except Exception as e:
        logging.error(f"Error in /auth_profile: {str(e)}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred'}), 500



# @two_factor.route('/auth_profile', methods=['GET'])
# @validate_api_key
# @validate_bearer_token
# @log_api_access
# def get_auth_profile():
#     try:
#         auth_header = request.headers.get('Authorization')
#         if not auth_header or not auth_header.startswith('Bearer '):
#             return jsonify({'error': 'Token is required'}), 401

#         token = auth_header.split(' ')[1]
#         try:
#             decoded_token = jwt.decode(
#                 token,
#                 current_app.config['SECRET_KEY'],
#                 algorithms=["HS256"]
#             )
#         except jwt.ExpiredSignatureError:
#             return jsonify({'error': 'Token has expired. Please log in again.'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'error': 'Invalid token. Please log in again.'}), 401

#         user = User.query.filter_by(id=decoded_token['id']).first()
#         if not user:
#             return jsonify({'error': 'User not found'}), 404

#         # First, try to get clinic_id directly from the user record.
#         clinic_id = user.clinic_id if hasattr(user, 'clinic_id') else None

#         user_role = "Unknown"
#         # Then try to get clinic information from ClinicTeam
#         clinic_team = ClinicTeam.query.filter_by(user_id=user.id).first()
#         if clinic_team:
#             # If clinic_team has a clinic_id, use it
#             if clinic_team.clinic_id:
#                 clinic_id = clinic_team.clinic_id
#             clinic_role = ClinicRoles.query.filter_by(id=clinic_team.clinic_role_id).first()
#             if clinic_role:
#                 user_role = clinic_role.role_name

#         # Fetch dashboards assigned to the user from the array column
#         dashboards_list = []
#         # NOTE: Adjust here if your column name is 'dashboard_ids' instead of 'dashboard_id'
#         if user.dashboard_id:
#             dashboards = Dashboard.query.filter(Dashboard.id.in_(user.dashboard_id)).all()
#             dashboards_list = [{
#                 "id": dash.id,
#                 "name": dash.name,
#                 "image": dash.image,
#                 "layout": dash.layout,
#             } for dash in dashboards]

#         profile_data = {
#             'id': user.id,
#             'email': user.email,
#             'first_name': user.first_name,
#             'last_name': user.last_name,
#             'role': decoded_token.get('role', 'user'),
#             'dashboards': dashboards_list,  # Return the list of assigned dashboards
#             'clinic_id': clinic_id,
#             'user_role': user_role
#         }

#         return jsonify({'message': 'Profile retrieved successfully', 'profile': profile_data}), 200

#     except Exception as e:
#         logging.error(f"Error in /auth_profile: {str(e)}", exc_info=True)
#         return jsonify({'error': 'An unexpected error occurred'}), 500

# ---------------
# @two_factor.route('/update_user_dashboards', methods=['PUT'])
# def update_user_dashboards():
#     try:
#         data = request.json
#         user_id = data.get('user_id')
#         dashboard_id = data.get('dashboard_id')  # Expecting a list of dashboard IDs

#         if not user_id or not dashboard_id:
#             return jsonify({'error': 'Both user_id and dashboard_id list are required.'}), 400

#         if not isinstance(dashboard_id, list):
#             return jsonify({'error': 'dashboard_id must be provided as a list.'}), 400

#         # Optionally, verify that each provided dashboard_id exists
#         valid_dashboards = Dashboard.query.filter(Dashboard.id.in_(dashboard_id)).all()
#         valid_dashboard_id = [dash.id for dash in valid_dashboards]
#         if not valid_dashboard_id:
#             return jsonify({'error': 'No valid dashboards found for the provided IDs.'}), 404

#         user = User.query.get(user_id)
#         if not user:
#             return jsonify({'error': 'User not found.'}), 404

#         # Update the user's dashboard_id column
#         user.dashboard_id = valid_dashboard_id
#         db.session.commit()

#         return jsonify({'message': 'User dashboard_id updated successfully.'}), 200

#     except Exception as e:
#         logging.error(f"Error updating user dashboard_id: {str(e)}", exc_info=True)
#         return jsonify({'error': 'An error occurred while updating user dashboard_id.'}), 500


@two_factor.route('/logout', methods=['POST'])
@validate_api_key
@validate_bearer_token
@log_api_access
@login_required
def logout():
    try:
        logout_user()
        session.pop('2fa_verified', None)
        return jsonify({'message': 'Logout successful.'}), 200
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred during logout'}), 500


# refresh_tokens = {}

# @auth.route('/refresh', methods=['POST'])
# def refresh():
#     try:
#         # Get the refresh token from the request
#         refresh_token = request.json.get('refresh_token')
        
#         if not refresh_token:
#             return jsonify({'error': 'Refresh token is required'}), 400

#         # Decode the refresh token
#         try:
#             decoded_token = jwt.decode(refresh_token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
#         except jwt.ExpiredSignatureError:
#             return jsonify({'error': 'Refresh token has expired'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'error': 'Invalid refresh token'}), 401

#         # Validate the refresh token
#         user_id = decoded_token.get('id')
#         if not user_id or refresh_tokens.get(user_id) != refresh_token:
#             return jsonify({'error': 'Invalid or revoked refresh token'}), 401

#         # Fetch the user from the database
#         user = User.query.get(user_id)
#         if not user:
#             return jsonify({'error': 'User not found'}), 404

#         # Generate a new access token
#         access_token = jwt.encode(
#             {
#                 'id': user.id,
#                 'email': user.email,
#                 'role': user.role.name,
#                 'exp': datetime.utcnow() + timedelta(minutes=15),  # 15-minute expiration
#                 'iat': datetime.utcnow()
#             },
#             current_app.config['SECRET_KEY'],
#             algorithm="HS256"
#         )

#         # Generate a new refresh token
#         new_refresh_token = jwt.encode(
#             {
#                 'id': user.id,
#                 'exp': datetime.utcnow() + timedelta(days=7),  # 7-day expiration
#                 'iat': datetime.utcnow()
#             },
#             current_app.config['SECRET_KEY'],
#             algorithm="HS256"
#         )

#         # Store the new refresh token
#         refresh_tokens[user.id] = new_refresh_token

#         # Respond with the new tokens
#         return jsonify({
#             'access_token': access_token,
#             'refresh_token': new_refresh_token
#         }), 200

#     except Exception as e:
#         return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500

