from functools import wraps
from flask import request, jsonify, g, current_app
from app.models import ApiKey, User, Role, Dashboard, APILog, ClinicTeam, ClinicRoles
from datetime import datetime
import jwt
from app import db
import os
import random

# Utility: Standard error response
def error_response(message, status_code, details=None):
    response = {'error': message}
    if details:
        response['details'] = details
    return jsonify(response), status_code

# Middleware to validate API key
def validate_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if not api_key:
            return error_response("API key is required in x-api-key header.", 401)
        valid_api_key = ApiKey.query.filter_by(api_key=api_key, is_active=True).first()
        if not valid_api_key:
            return error_response("Invalid or inactive API key.", 403)
        g.api_key = valid_api_key
        return f(*args, **kwargs)
    return decorated_function

# Middleware to validate Bearer token
def validate_bearer_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production you might enforce validation; adjust as needed.
        if os.environ.get('FLASK_ENV') == 'production':
            return f(*args, **kwargs)
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return error_response("Bearer token is required in Authorization header.", 401)
        try:
            bearer_token = auth_header.split('Bearer ')[1]
            decoded_token = jwt.decode(
                bearer_token,
                current_app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )
            user = User.query.filter_by(id=decoded_token.get('id')).first()
            if not user or not user.is_active:
                return error_response("Invalid or expired Bearer token.", 403)
            g.user = user
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return error_response("Bearer token has expired.", 403)
        except jwt.InvalidTokenError:
            return error_response("Invalid Bearer token.", 403)
        except Exception as e:
            return error_response("Error validating Bearer token.", 500, str(e))
    return decorated_function

# Middleware to validate user role
def validate_user_role(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if not hasattr(g, 'user') or not g.user:
                    return error_response("Unauthorized request. User is not authenticated.", 401)
                user_role = Role.query.get(g.user.role_id)
                if not user_role:
                    return error_response("Access denied. User role not found.", 403)
                if user_role.name.lower() not in [role.lower() for role in required_roles]:
                    return error_response("Access denied.", 403)
                g.role = user_role
                return f(*args, **kwargs)
            except Exception as e:
                return error_response("Error validating user role.", 500, str(e))
        return decorated_function
    return decorator

# Middleware to validate user dashboard (legacy single dashboard)
def validate_user_dashboard(required_dashboards):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if not hasattr(g, 'user') or not g.user:
                    return error_response("Unauthorized request. User is not authenticated.", 401)
                # Here, we assume the dashboard is stored as a single integer.
                dashboard = Dashboard.query.filter_by(id=getattr(g.user, 'dashboard_id', None)).first()
                if not dashboard:
                    return error_response("User does not have a valid dashboard assigned.", 403)
                if dashboard.name not in required_dashboards:
                    return error_response(f"Access denied. Dashboard '{dashboard.name}' not allowed.", 403)
                g.dashboard = dashboard
                return f(*args, **kwargs)
            except Exception as e:
                return error_response("Error validating user dashboard access.", 500, str(e))
        return decorated_function
    return decorator

# Middleware to log API access
def log_api_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            api_key = request.headers.get('x-api-key', 'Unknown')
            system = ApiKey.query.filter_by(api_key=api_key).first()
            system_name = system.system_name if system else "Unknown System"
            user_email = "Unknown User"
            app_name = "Unknown App"
            ip_address = request.remote_addr

            if hasattr(g, 'user') and g.user:
                user_email = g.user.email
                # Fix: If the user's dashboard field is an array, use .in_()
                if getattr(g.user, 'dashboard_id', None):
                    if isinstance(g.user.dashboard_id, list):
                        dashboard = Dashboard.query.filter(Dashboard.id.in_(g.user.dashboard_id)).first()
                    else:
                        dashboard = Dashboard.query.filter_by(id=g.user.dashboard_id).first()
                else:
                    dashboard = None
                app_name = dashboard.name if dashboard else "Unknown App"

            # Execute route logic
            response = f(*args, **kwargs)
            status_code = response[1] if isinstance(response, tuple) else response.status_code

            # Before logging, ensure session is not in an aborted state.
            db.session.rollback()

            log_entry = APILog(
                system_name=system_name,
                user_email=user_email,
                ip_address=ip_address,
                app_name=app_name,
                endpoint=request.path,
                method=request.method,
                status_code=status_code,
                accessed_at=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()
            return response

        except Exception as e:
            db.session.rollback()
            return error_response("Error logging API access.", 500, str(e))
    return decorated_function

# Utility: Generate a 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))
