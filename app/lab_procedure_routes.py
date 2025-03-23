from flask import Blueprint, request, jsonify, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash
from app import db  # Correctly importing db from the app module
from app.models import Procedure, ProcedureOption, APILog, ApiKey, ProcedureStep, ProcedureOption
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

lab_procedure_routes = Blueprint('lab_procedure_routes', __name__)

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


def log_api_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            api_key = request.headers.get('x-api-key', 'Unknown')

            system = ApiKey.query.filter_by(api_key=api_key).first()
            system_name = system.system_name if system else 'Unknown System'

            response = f(*args, **kwargs)

            if isinstance(response, tuple):
                response_body, status_code = response[0], response[1]
            else:
                status_code = response.status_code

            log_entry = APILog(
                system_name=system_name,
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
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

    return decorated_function

# create procedure
@lab_procedure_routes.route('/procedure/create', methods=['POST'])
# @log_api_access
# @require_api_key
def add_procedure():
    try:
        user_id = request.json.get('user_id')  # Ensure user_id is an integer
        procedure_name = request.json.get('procedure_name')
        cost = request.json.get('cost')
        code = request.json.get('code')
        options = request.json.get('options', [])  # Procedure options
        steps = request.json.get('procedure_steps', [])  # Procedure steps

        # Validate required fields
        if not procedure_name or not cost or not code or not user_id:
            return jsonify({'error': 'Procedure name, cost, code, and user_id are required.'}), 400

        # Ensure user_id is an integer
        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({'error': 'Invalid user_id. Must be an integer.'}), 400

        # Check if procedure name or code already exists
        if Procedure.query.filter((Procedure.procedure_name == procedure_name) | (Procedure.code == code)).first():
            return jsonify({'error': 'Procedure name or code already exists.'}), 400

        # Create new procedure
        new_procedure = Procedure(
            procedure_name=procedure_name,
            cost=cost,
            code=code,
            user_id=user_id
        )
        db.session.add(new_procedure)
        db.session.commit()

        # Get the procedure ID as an integer
        procedure_id_int = new_procedure.id

        # Add procedure options
        if options:
            for option in options:
                option_name = option.get('name')
                additional_cost = option.get('additional_cost', 0)

                if option_name:
                    if ProcedureOption.query.filter_by(procedure_id=procedure_id_int, option_name=option_name).first():
                        continue

                    new_option = ProcedureOption(
                        procedure_id=procedure_id_int,  # Ensure integer
                        option_name=option_name,
                        additional_cost=additional_cost
                    )
                    db.session.add(new_option)

        # Add procedure steps
        if steps:
            for step in steps:
                step_number = step.get('step_number')
                step_name = step.get('step_name')
                step_description = step.get('step_description', '')
                step_price = step.get('step_price', 0)
                created_by = user_id  # Ensure this is stored as an integer

                if step_number and step_name:
                    new_step = ProcedureStep(
                        procedure_id=procedure_id_int,  # Ensure integer
                        step_number=int(step_number),  # Ensure integer
                        step_name=step_name,
                        step_description=step_description,
                        step_price=float(step_price),  # Ensure float (decimal)
                        created_by=int(created_by),  # Ensure integer
                    )
                    db.session.add(new_step)

        # Commit all changes
        db.session.commit()

        return jsonify({'message': 'Procedure added successfully.', 'procedure_id': procedure_id_int}), 201

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': str(e)}), 500


# get all procedures
@lab_procedure_routes.route('/procedure/get_all', methods=['GET'])
@log_api_access
@require_api_key
def get_all_procedures():
    try:
        procedures = Procedure.query.all()

        if not procedures:
            return jsonify({'message': 'No procedures found.'}), 404

        procedures_list = []
        for procedure in procedures:
            # Fetch associated options and steps for each procedure
            options = ProcedureOption.query.filter_by(procedure_id=procedure.id).all()
            steps = ProcedureStep.query.filter_by(procedure_id=procedure.id).all()

            # Prepare procedure data with options and steps
            procedure_data = {
                'id': procedure.id,
                'procedure_name': procedure.procedure_name,
                'cost': procedure.cost,
                'code': procedure.code,
                'user_id': procedure.user_id,
                'created_at': procedure.created_at,
                'options': [],
                'steps': []
            }

            # Add options to the procedure data
            for option in options:
                procedure_data['options'].append({
                    'option_id': option.id,  # Add option_id
                    'option_name': option.option_name,
                    'additional_cost': option.additional_cost
                })

            # Add steps to the procedure data
            for step in steps:
                procedure_data['steps'].append({
                    'step_id': step.id,  # Add step_id
                    'step_number': step.step_number,
                    'step_name': step.step_name,
                    'step_description': step.step_description,
                    'step_price': step.step_price
                })

            # Add procedure data to the list
            procedures_list.append(procedure_data)

        return jsonify({'procedures': procedures_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# get procedure by id
@lab_procedure_routes.route('/procedure/<int:procedure_id>', methods=['GET'])
@log_api_access
def get_procedure_by_id(procedure_id):
    try:
        procedure = Procedure.query.get(procedure_id)

        if not procedure:
            return jsonify({'error': 'Procedure not found.'}), 404

        # Fetch associated options and steps for the procedure
        options = ProcedureOption.query.filter_by(procedure_id=procedure_id).all()
        steps = ProcedureStep.query.filter_by(procedure_id=procedure_id).all()

        procedure_data = {
            'id': procedure.id,
            'procedure_name': procedure.procedure_name,
            'cost': procedure.cost,
            'code': procedure.code,
            'user_id': procedure.user_id,
            'created_at': procedure.created_at,
            'options': [],
            'steps': []
        }

        # Add options to the procedure data
        for option in options:
            procedure_data['options'].append({
                'option_name': option.option_name,
                'additional_cost': option.additional_cost
            })

        # Add steps to the procedure data
        for step in steps:
            procedure_data['steps'].append({
                'step_number': step.step_number,
                'step_name': step.step_name,
                'step_description': step.step_description,
                'step_price': step.step_price,
                'created_at': step.date_created
            })

        return jsonify({'procedure': procedure_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@lab_procedure_routes.route('/procedure/<int:procedure_id>', methods=['PUT'])
@log_api_access
@require_api_key
def update_procedure(procedure_id):
    try:
        with db.session.no_autoflush:
            procedure = Procedure.query.get(procedure_id)

            if not procedure:
                return jsonify({'error': 'Procedure not found.'}), 404

            procedure_name = request.json.get('procedure_name', procedure.procedure_name)
            cost = request.json.get('cost', procedure.cost)
            code = request.json.get('code', procedure.code)
            options = request.json.get('options', [])
            procedure_steps = request.json.get('procedure_steps', [])

            # Update procedure fields
            procedure.procedure_name = procedure_name
            procedure.cost = cost
            procedure.code = code

            # Update procedure options
            if options:
                existing_options = ProcedureOption.query.filter_by(procedure_id=procedure_id).all()
                existing_option_names = [option.option_name for option in existing_options]

                for option in options:
                    option_name = option.get('option_name')
                    additional_cost = option.get('additional_cost')

                    if option_name and additional_cost is not None:
                        if option_name in existing_option_names:
                            # Update existing option if found
                            existing_option = next(opt for opt in existing_options if opt.option_name == option_name)
                            existing_option.additional_cost = additional_cost
                        else:
                            # Add new option if not found
                            new_option = ProcedureOption(
                                procedure_id=procedure_id,
                                option_name=option_name,
                                additional_cost=additional_cost
                            )
                            db.session.add(new_option)

                # Remove options that were removed from the request
                for existing_option in existing_options:
                    if existing_option.option_name not in [option.get('option_name') for option in options]:
                        db.session.delete(existing_option)

            # Update procedure steps
            if procedure_steps:
                existing_steps = ProcedureStep.query.filter_by(procedure_id=procedure_id).all()
                existing_step_numbers = [step.step_number for step in existing_steps]

                for step in procedure_steps:
                    step_number = step.get('step_number')
                    step_name = step.get('step_name')
                    step_description = step.get('step_description', '')
                    step_price = step.get('step_price', 0.00)

                    if step_number in existing_step_numbers:
                        # Update existing step if found
                        existing_step = next(s for s in existing_steps if s.step_number == step_number)
                        existing_step.step_name = step_name
                        existing_step.step_description = step_description
                        existing_step.step_price = step_price
                    else:
                        # Add new step if not found
                        new_step = ProcedureStep(
                            procedure_id=procedure_id,
                            step_number=step_number,
                            step_name=step_name,
                            step_description=step_description,
                            step_price=step_price,
                            created_by=procedure.user_id  # Assuming created_by is the user_id of the procedure creator
                        )
                        db.session.add(new_step)

                # Remove steps that were removed from the request
                for existing_step in existing_steps:
                    if existing_step.step_number not in [step.get('step_number') for step in procedure_steps]:
                        db.session.delete(existing_step)

        db.session.commit()

        return jsonify({'message': 'Procedure, options, and steps updated successfully.', 'procedure_id': procedure.id}), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': str(e)}), 500


# Delete procedure
@lab_procedure_routes.route('/procedure/<int:procedure_id>', methods=['DELETE'])
@log_api_access
@require_api_key
def delete_procedure(procedure_id):
    try:
        # Begin a block where autoflush is disabled to prevent locking
        with db.session.no_autoflush:
            # Get the procedure object by its ID
            procedure = Procedure.query.get(procedure_id)

            # If procedure is not found, return an error
            if not procedure:
                return jsonify({'error': 'Procedure not found.'}), 404

            # Delete associated options for this procedure
            db.session.query(ProcedureOption).filter_by(procedure_id=procedure_id).delete()
            db.session.flush()  # Explicit flush to apply the delete to procedure options

            # Delete associated steps for this procedure
            db.session.query(ProcedureStep).filter_by(procedure_id=procedure_id).delete()
            db.session.flush()  # Explicit flush to apply the delete to procedure steps

            # Now delete the procedure itself
            db.session.delete(procedure)

        # Commit the transaction to delete the procedure, options, and steps
        db.session.commit()

        return jsonify({'message': 'Procedure, its options, and steps deleted successfully.'}), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': str(e)}), 500



@lab_procedure_routes.route('/procedure/<string:procedure_id>/steps', methods=['GET'])
def get_procedure_steps(procedure_id):
    try:
        steps = db.session.query(
            ProcedureStep.id,
            ProcedureStep.procedure_id,
            ProcedureStep.step_name,
            ProcedureStep.step_price,
            ProcedureStep.date_created,
            ProcedureStep.step_description
        ).filter(ProcedureStep.procedure_id == procedure_id).order_by(ProcedureStep.date_created).all()

        if not steps:
            return jsonify({'error': 'No steps found for this procedure'}), 404

        steps_list = [{
            'step_id': step.id,
            'step_name': step.step_name,
            'step_price': step.step_price,
            'step_name': step.step_name,
            # 'description': step.description,
            # 'order': step.order
        } for step in steps]

        return jsonify({'procedure_id': procedure_id, 'steps': steps_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@lab_procedure_routes.route('/procedure/<string:procedure_id>/options', methods=['GET'])
def get_procedure_options(procedure_id):
    try:
        options = db.session.query(
            ProcedureOption.id,
            ProcedureOption.procedure_id,
            ProcedureOption.option_name,
            # ProcedureOption.description,
            ProcedureOption.additional_cost
        ).filter(ProcedureOption.procedure_id == procedure_id).all()

        if not options:
            return jsonify({'error': 'No options found for this procedure'}), 404

        options_list = [{
            'option_id': option.id,
            'procedure_id': option.procedure_id,
            'option_name': option.option_name,
            'additional_cost': float(option.additional_cost)  # Convert cost to float for JSON compatibility
        } for option in options]

        return jsonify({'procedure_id': procedure_id, 'options': options_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@lab_procedure_routes.route('/procedure/details/<int:procedure_id>', methods=['GET'])
def get_procedure_details(procedure_id):
    try:
        # Fetch procedure details from database
        procedure = Procedure.query.filter_by(id=procedure_id).first()

        if not procedure:
            return jsonify({'error': 'Procedure not found'}), 404

        # Return procedure details (name and cost)
        return jsonify({
            'procedure_name': procedure.procedure_name,
            'cost': float(procedure.cost)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500