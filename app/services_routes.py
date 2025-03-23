from flask import Blueprint, request, jsonify, session, redirect, url_for, g
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import APILog, ApiKey, ServiceCategory, Service, ServiceTreatmentArea, TreatmentOption, TreatmentOptionValue, User
import random, secrets
import string
import re
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from functools import wraps
from datetime import datetime
from app import db

services_routes = Blueprint('services_routes', __name__)
AUTH_SYSTEM_URL = "http://192.168.100.16:5000/api"


# Service Catgory APIS
@services_routes.route('/service_categories', methods=['POST'])
def add_service_category():
    data = request.get_json()

    # Validate input data
    if not data or not data.get('category') or not data.get('clinic_id'):
        return jsonify({'error': 'Category and Clinic ID are required'}), 400

    # Create a new service category
    new_category = ServiceCategory(
        category=data['category'],
        clinic_id=data['clinic_id']
    )

    try:
        db.session.add(new_category)
        db.session.commit()
        return jsonify({'message': 'Service category created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@services_routes.route('/service_categories/<int:id>', methods=['PUT'])
def edit_service_category(id):
    data = request.get_json()

    # Validate input data
    if not data or not data.get('category') or not data.get('clinic_id'):
        return jsonify({'error': 'Category and Clinic ID are required'}), 400

    # Retrieve the service category by ID
    category = ServiceCategory.query.get(id)
    if not category:
        return jsonify({'error': 'Service category not found'}), 404

    # Update the service category
    category.category = data['category']
    category.clinic_id = data['clinic_id']

    try:
        db.session.commit()
        return jsonify({'message': 'Service category updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@services_routes.route('/service_categories', methods=['GET'])
def get_service_categories():
    categories = ServiceCategory.query.all()
    if not categories:
        return jsonify({'message': 'No service categories found'}), 404

    categories_list = [{'id': category.id, 'category': category.category, 'clinic_id': category.clinic_id} for category in categories]
    return jsonify({'service_categories': categories_list}), 200


# Service treatment area APIS
@services_routes.route('/create_treatment_area', methods=['POST'])
def create_treatment_area():
    # Get the JSON data from the request body
    data = request.get_json()

    # Extract the clinic_id and treatment_area from the request data
    clinic_id = data.get('clinic_id')
    treatment_area = data.get('treatment_area')

    # Validate the data
    if not clinic_id or not treatment_area:
        return jsonify({'error': 'clinic_id and treatment_area are required'}), 400

    # Create a new ServiceTreatmentArea object
    new_treatment_area = ServiceTreatmentArea(
        clinic_id=clinic_id,
        treatment_area=treatment_area
    )

    try:
        # Add the new treatment area to the database
        db.session.add(new_treatment_area)
        db.session.commit()

        return jsonify({
            'message': 'Treatment area created successfully',
            'treatment_area': {
                'id': new_treatment_area.id,
                'clinic_id': new_treatment_area.clinic_id,
                'treatment_area': new_treatment_area.treatment_area,
                'created_at': new_treatment_area.created_at
            }
        }), 201
    except Exception as e:
        # In case of an error, rollback the session
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Treatment Areas API
@services_routes.route('/treatment_areas', methods=['GET'])
def get_all_treatment_areas():
    try:
        # Fetch all treatment areas from the database
        treatment_areas = ServiceTreatmentArea.query.all()

        if not treatment_areas:
            return jsonify({"error": "No treatment areas found"}), 404

        # Manually extract attributes from each treatment area object
        treatment_area_list = []
        for area in treatment_areas:
            treatment_area_list.append({
                "id": area.id,
                "clinic_id": area.clinic_id,
                "treatment_area": area.treatment_area,
                "created_at": area.created_at
            })

        return jsonify({
            "message": "Treatment areas fetched successfully",
            "treatment_areas": treatment_area_list
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch treatment areas", "details": str(e)}), 500


# Services APIS
@services_routes.route('/services', methods=['POST'])
def create_service():
    try:
        data = request.get_json()

        # Required fields validation
        required_fields = ["clinic_id", "category_id", "code", "description", "office_code", "amount_il", "amount_wi"]
        for field in required_fields:
            if field not in data or data[field] is None:
                return jsonify({"error": f"'{field}' is required"}), 400

        # Create a new service entry (only required fields)
        new_service = Service(
            clinic_id=data['clinic_id'],
            category_id=data['category_id'],
            code=data['code'],
            description=data['description'],
            office_code=data['office_code'],
            amount_il=float(data['amount_il']),
            amount_wi=float(data['amount_wi'])
        )

        # Handle optional fields (if provided)
        new_service.user_id = data.get('user_id')
        new_service.treatment_area_id = data.get('treatment_area_id')
        new_service.treatment_area2_id = data.get('treatment_area2_id')
        new_service.image = data.get('image')

        db.session.add(new_service)
        db.session.commit()

        return jsonify({
            "message": "Service created successfully",
            "service_id": new_service.id
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to create service", "details": str(e)}), 500


# Services APIS
@services_routes.route('/services/<int:id>', methods=['PUT'])
def update_service(id):
    try:
        data = request.get_json()

        # Required fields validation for the update
        required_fields = ["clinic_id", "category_id", "code", "description", "office_code", "amount_il", "amount_wi"]
        for field in required_fields:
            if field not in data or data[field] is None:
                return jsonify({"error": f"'{field}' is required"}), 400

        # Fetch the existing service entry by id
        service_to_update = Service.query.get(id)

        if not service_to_update:
            return jsonify({"error": "Service not found"}), 404

        # Update the service fields
        service_to_update.clinic_id = data['clinic_id']
        service_to_update.category_id = data['category_id']
        service_to_update.code = data['code']
        service_to_update.description = data['description']
        service_to_update.office_code = data['office_code']
        service_to_update.amount_il = float(data['amount_il'])
        service_to_update.amount_wi = float(data['amount_wi'])

        # Handle optional fields (if provided)
        service_to_update.user_id = data.get('user_id', service_to_update.user_id)  # Keep existing value if not provided
        service_to_update.treatment_area_id = data.get('treatment_area_id', service_to_update.treatment_area_id)
        service_to_update.treatment_area2_id = data.get('treatment_area2_id', service_to_update.treatment_area2_id)
        service_to_update.image = data.get('image', service_to_update.image)

        # Commit the changes to the database
        db.session.commit()

        return jsonify({
            "message": "Service updated successfully",
            "service_id": service_to_update.id
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update service", "details": str(e)}), 500


# Services APIs
@services_routes.route('/services', methods=['GET'])
def get_all_services():
    try:
        # Fetch all services with user details (joining with User table)
        services = (
            db.session.query(
                Service.id,
                Service.clinic_id,
                Service.category_id,
                Service.code,
                Service.description,
                Service.office_code,
                Service.amount_il,
                Service.amount_wi,
                Service.user_id,
                Service.treatment_area_id,
                Service.treatment_area2_id,
                Service.image,
                Service.created_at,
                User.first_name,
                User.last_name
            )
            .outerjoin(User, Service.user_id == User.id)  # Join with User table
            .all()
        )

        if not services:
            return jsonify({"error": "No services found"}), 404

        service_list = [
            {
                "id": service.id,
                "clinic_id": service.clinic_id,
                "category_id": service.category_id,
                "code": service.code,
                "description": service.description,
                "office_code": service.office_code,
                "amount_il": f"{float(service.amount_il):.2f}" if service.amount_il is not None else "0.00",
                "amount_wi": f"{float(service.amount_wi):.2f}" if service.amount_wi is not None else "0.00",
                "user_id": service.user_id,
                "user_name": f"{service.first_name} {service.last_name}".strip() if service.first_name else "Unknown",
                "treatment_area_id": service.treatment_area_id,
                "treatment_area2_id": service.treatment_area2_id,
                "image": service.image,
                "created_at": service.created_at.strftime('%Y-%m-%d %H:%M:%S') if service.created_at else None
            }
            for service in services
        ]

        return jsonify({
            "message": "Services fetched successfully",
            "services": service_list
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch services", "details": str(e)}), 500

# Services APIs
@services_routes.route('/services/<int:service_id>', methods=['GET'])
def get_service_by_id(service_id):
    try:
        # Fetch the service by ID from the database
        service = Service.query.get(service_id)

        if not service:
            return jsonify({"error": "Service not found"}), 404

        # Manually extract attributes from the service object
        service_data = {
            "id": service.id,
            "clinic_id": service.clinic_id,
            "category_id": service.category_id,
            "code": service.code,
            "description": service.description,
            "office_code": service.office_code,
            "amount_il": service.amount_il,
            "amount_wi": service.amount_wi,
            "user_id": service.user_id,
            "treatment_area_id": service.treatment_area_id,
            "treatment_area2_id": service.treatment_area2_id,
            "image": service.image,
            "created_at": service.created_at
        }

        return jsonify({
            "message": "Service fetched successfully",
            "service": service_data
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch service", "details": str(e)}), 500


# treatment options things
@services_routes.route('/create_treatment_option', methods=['POST'])
def create_treatment_option():
    try:
        data = request.json
        treatment_id = data.get('treatment_id')
        options = data.get('options')  # List of options with values

        if not treatment_id or not options:
            return jsonify({"error": "Missing treatment_id or options"}), 400

        created_options = []

        for option in options:
            option_name = option.get('option_name')
            option_type = option.get('option_type')
            values = option.get('values', [])  # List of values

            if not option_name or not option_type:
                return jsonify({"error": "Missing option_name or option_type"}), 400

            # Create treatment option
            new_option = TreatmentOption(
                treatment_id=treatment_id,
                option_name=option_name,
                option_type=option_type
            )
            db.session.add(new_option)
            db.session.flush()  # Get new_option.id before commit

            # Add values to treatment_option_values
            for value in values:
                new_value = TreatmentOptionValue(
                    option_id=new_option.id,
                    value=value
                )
                db.session.add(new_value)

            created_options.append({
                "option_id": new_option.id,
                "option_name": new_option.option_name,
                "option_type": new_option.option_type,
                "values": values
            })

        db.session.commit()

        return jsonify({
            "message": "Treatment options created successfully",
            "data": created_options
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



@services_routes.route('/service/<int:service_id>/treatment_options', methods=['GET'])
def get_treatment_options_by_service(service_id):
    try:
        # Fetch the service by ID
        service = Service.query.filter_by(id=service_id).first()
        if not service:
            return jsonify({"error": "Service not found"}), 404

        # Ensure treatment_area_id exists
        if not service.treatment_area_id:
            return jsonify({"error": "Treatment area not assigned to this service"}), 400

        # Fetch treatment options linked to the treatment_area_id
        treatment_options = TreatmentOption.query.filter_by(treatment_id=service.treatment_area_id).all()

        if not treatment_options:
            return jsonify({"message": "No treatment options found for this treatment area"}), 200

        options_data = []

        for option in treatment_options:
            # Get values linked to this option_id
            values = TreatmentOptionValue.query.filter_by(option_id=option.id).all()

            options_data.append({
                "option_id": option.id,
                "option_name": option.option_name,
                "option_type": option.option_type,
                "status": "active" if option.status == 1 else "inactive",  # Convert status
                "values": [v.value for v in values]  # Extract value list
            })

        return jsonify({
            "service_id": service.id,
            "treatment_area_id": service.treatment_area_id,
            "treatment_options": options_data
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@services_routes.route('/treatment_option/<int:option_id>', methods=['PUT'])
def update_treatment_option(option_id):
    try:
        data = request.json

        # Fetch the treatment option
        treatment_option = TreatmentOption.query.filter_by(id=option_id).first()

        if not treatment_option:
            return jsonify({"error": "Treatment option not found"}), 404

        # Update fields if provided
        if "option_name" in data:
            treatment_option.option_name = data["option_name"]
        if "option_type" in data:
            treatment_option.option_type = data["option_type"]
        if "status" in data:
            treatment_option.status = 1 if data["status"].lower() == "active" else 0

        db.session.commit()  # Commit updates

        return jsonify({
            "message": "Treatment option updated successfully",
            "updated_treatment_option": {
                "option_id": treatment_option.id,
                "option_name": treatment_option.option_name,
                "option_type": treatment_option.option_type,
                "status": "Active" if treatment_option.status == 1 else "Inactive"
            }
        }), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({"error": str(e)}), 500