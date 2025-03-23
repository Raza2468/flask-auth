from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from app import db
from app.models import Clinic, InsuranceCompany, ApiKey, APILog
from datetime import datetime
from functools import wraps
from sqlalchemy.exc import IntegrityError

# Blueprint for insurance companies routes
insurance_companies_bp = Blueprint('insurance_companies_bp', __name__)

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


# POST: Create an insurance company
@insurance_companies_bp.route('/insurance_company', methods=['POST'])
@require_api_key
@log_api_access
def create_insurance_company():
    data = request.get_json()
    required_fields = ['name', 'short_name', 'address', 'phone', 'email']
    
    # Check for missing fields
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({"message": f"Missing fields: {', '.join(missing_fields)}"}), 400

    # Validate clinic_id
    clinic = Clinic.query.filter_by(id=data['clinic_id']).first()
    if not clinic:
        return jsonify({"message": "Invalid clinic_id. Clinic not found."}), 400

    # Validate email format
    if '@' not in data['email'] or '.' not in data['email']:
        return jsonify({"message": "Invalid email format."}), 400

    try:
        # Create a new insurance company
        new_company = InsuranceCompany(
            name=data['name'],
            clinic_id=data['clinic_id'],
            short_name=data['short_name'],
            address=data['address'],
            phone=data['phone'],
            email=data['email'],
            website=data.get('website')
        )
        db.session.add(new_company)
        db.session.commit()

        return jsonify({
            "message": "Insurance company created successfully",
            "company": new_company.to_dict()
        }), 201

    except IntegrityError as e:
        db.session.rollback()
        return jsonify({"message": "Database error", "details": str(e.orig)}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An unexpected error occurred", "details": str(e)}), 500


# GET: Fetch all insurance companies
@insurance_companies_bp.route('/insurance_company', methods=['GET'])
@require_api_key
@log_api_access
def get_insurance_companies():
    companies = InsuranceCompany.query.all()
    return jsonify({
        "message": "Insurance companies fetched successfully",
        "companies": [company.to_dict() for company in companies]
    }), 200


# GET: Fetch insurance company by ID
@insurance_companies_bp.route('/insurance_company/<int:company_id>', methods=['GET'])
@require_api_key
@log_api_access
def get_insurance_company_by_id(company_id):
    company = InsuranceCompany.query.filter_by(id=company_id).first()
    if not company:
        return jsonify({"message": "Insurance company not found"}), 404

    return jsonify({
        "message": "Insurance company fetched successfully",
        "company": company.to_dict()
    }), 200


# PUT: Update insurance company
@insurance_companies_bp.route('/insurance_company/<int:company_id>', methods=['PUT'])
@require_api_key
@log_api_access
def update_insurance_company(company_id):
    data = request.get_json()
    company = InsuranceCompany.query.filter_by(id=company_id).first()

    if not company:
        return jsonify({"message": "Insurance company not found"}), 404

    try:
        company.name = data.get('name', company.name)
        company.short_name = data.get('short_name', company.short_name)
        company.address = data.get('address', company.address)
        company.phone = data.get('phone', company.phone)
        company.email = data.get('email', company.email)
        company.website = data.get('website', company.website)
        db.session.commit()

        return jsonify({
            "message": "Insurance company updated successfully",
            "company": company.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An unexpected error occurred", "details": str(e)}), 500


# DELETE: Delete insurance company
@insurance_companies_bp.route('/insurance_company/<int:company_id>', methods=['DELETE'])
@require_api_key
@log_api_access
def delete_insurance_company(company_id):
    company = InsuranceCompany.query.filter_by(id=company_id).first()

    if not company:
        return jsonify({"message": "Insurance company not found"}), 404

    try:
        db.session.delete(company)
        db.session.commit()

        return jsonify({"message": "Insurance company deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An unexpected error occurred", "details": str(e)}), 500







from flask import Blueprint, request, jsonify
from app import db
from app.models import InsurancePayer
import os
import fitz  # PyMuPDF
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from app import db
from app.models import InsurancePayer
import tempfile

# Define Blueprint for Insurance routes
ALLOWED_EXTENSIONS = {"pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@insurance_companies_bp.route("/insurance/upload", methods=["POST"])
def upload_insurance_pdf():
    """API to upload PDF, extract payers, and insert into DB."""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # ✅ Use a temporary directory for saving the file
            temp_dir = tempfile.gettempdir()
            filepath = os.path.join(temp_dir, filename)

            file.save(filepath)  # ✅ Now it will save successfully
            # ✅ Extract data from PDF
            extracted_payers = extract_payers_from_pdf(filepath)

            # ✅ Insert into DB
            inserted_count = insert_payers_into_db(extracted_payers)

            return jsonify({"message": f"{inserted_count} payers inserted successfully!"}), 201

        return jsonify({"error": "Invalid file type. Only PDFs allowed!"}), 400

    except Exception as e:
        return jsonify({"error": "Failed to process file", "details": str(e)}), 500

# ✅ Function to extract payer details from PDF
def extract_payers_from_pdf(filepath):
    extracted_payers = []
    
    with fitz.open(filepath) as pdf:
        for page in pdf:
            text = page.get_text("text")
            lines = text.split("\n")

            for line in lines:
                parts = line.split(maxsplit=1)
                if len(parts) == 2 and parts[0].isalnum():
                    payer_code, payer_name = parts
                    extracted_payers.append({"payer_code": payer_code, "payer_name": payer_name})

    return extracted_payers

# ✅ Function to insert extracted payers into the database
def insert_payers_into_db(payers):
    inserted_count = 0
    for payer in payers:
        if not payer["payer_code"] or not payer["payer_name"]:
            continue  # Skip if missing data

        # Check if already exists
        existing_payer = InsurancePayer.query.filter_by(payer_code=payer["payer_code"]).first()
        if not existing_payer:
            new_payer = InsurancePayer(
                payer_code=payer["payer_code"],
                payer_name=payer["payer_name"]
            )
            db.session.add(new_payer)
            inserted_count += 1

    db.session.commit()
    return inserted_count