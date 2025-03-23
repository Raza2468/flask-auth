from flask import Flask
from flask_login import LoginManager
from .extensions import db, migrate
from flask_cors import CORS
import os

def create_app():
    app = Flask(__name__)
    

    # Select configuration using the FLASK_CONFIG environment variable.
    # If not set, default to 'config.ProductionConfig' (or switch to DevelopmentConfig if needed).
    config_name = os.environ.get('FLASK_CONFIG', 'config.ProductionConfig')
    app.config.from_object(config_name)
    
    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app, supports_credentials=True)
    
    # Initialize the login manager
    login_manager = LoginManager(app)
    login_manager.init_app(app)

    # Define the user loader function for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))

    # Register blueprints
    from app.clinic_routes import clinic
    from app.user_routes import user
    from app.roles_management import role
    from app.clinic_location_routes import clinic_locations
    from app.patient_routes import patient
    from app.clinic_providers_route import clinic_providers
    from app.clinic_roles import clinic_roles
    from app.clinic_team_route import clinic_team
    from app.insurance_routes import insurance
    from app.lab_procedure_routes import lab_procedure_routes
    from app.routes import main
    from app.two_factor_routes import two_factor  # Import the new 2FA blueprint
    from app.insurance_companies import insurance_companies_bp
    from app.dashboard_routes import dashboards_bp
    from app.services_routes import services_routes
    from app.status_routes import status_routes
    from app.assign_dashboard_routes import dashboard_api

    # Register the blueprints with the appropriate URL prefixes
    app.register_blueprint(main)
    app.register_blueprint(clinic, url_prefix='/api')
    app.register_blueprint(user, url_prefix='/api')
    app.register_blueprint(role, url_prefix='/api')
    app.register_blueprint(clinic_locations, url_prefix='/api')
    app.register_blueprint(patient, url_prefix='/api')
    app.register_blueprint(clinic_providers, url_prefix='/api')
    app.register_blueprint(clinic_roles, url_prefix='/api')
    app.register_blueprint(clinic_team, url_prefix='/api')
    app.register_blueprint(insurance, url_prefix='/api')
    app.register_blueprint(two_factor, url_prefix='/api') 
    app.register_blueprint(lab_procedure_routes, url_prefix='/api')
    app.register_blueprint(insurance_companies_bp, url_prefix='/api')
    app.register_blueprint(dashboards_bp, url_prefix='/api')
    app.register_blueprint(services_routes, url_prefix='/api')
    app.register_blueprint(status_routes, url_prefix='/api')
    app.register_blueprint(dashboard_api, url_prefix='/api')

    return app

app = create_app()
