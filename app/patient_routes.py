from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from app.extensions import db
from app.utils import AESCipher
import os
from dotenv import load_dotenv
from app.models import Clinic, Patient
from functools import wraps
from app.util.decorators import log_api_access, validate_api_key, validate_bearer_token
import base64
# from datetime import datetime
# import os
# import pandas as pd
# import base64
# from flask import request, jsonify, Blueprint
# from werkzeug.utils import secure_filename
# from app.models import db, Patient
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import padding
load_dotenv()
cipher = AESCipher(key=os.getenv('ENCRYPTION_KEY', 'default_encryption_key'))

patient = Blueprint('patient', __name__)

def parse_date(date_str):
    """Convert string to date object."""
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return None

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

# Ensure this key matches the one used in encryption
SECRET_KEY = b'12345678901234567890123456789012'  # Ensure 32-byte key
IV = b'1234567890123456'  # Ensure 16-byte IV (matches encryption)

def decrypt_value(encrypted_value):
    """Decrypt AES encrypted value, handling both prefixed and non-prefixed formats."""
    try:
        if not encrypted_value:
            return None

        if encrypted_value.startswith("ENC::"):
            # Remove prefix and decode base64
            encrypted_data = base64.b64decode(encrypted_value[5:])
        else:
            # Assume it's raw base64 encoded ciphertext
            encrypted_data = base64.b64decode(encrypted_value)

        # Initialize AES cipher (must match encryption settings)
        cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt data
        decrypted_padded_value = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_value = unpadder.update(decrypted_padded_value) + unpadder.finalize()

        return decrypted_value.decode()  # Convert bytes back to string
    except Exception as e:
        print(f"Decryption Error: {str(e)}")
        return None  # Return None in case of failure

def decrypt_patient_enc(patient):
    """Decrypt patient data for response."""
    try:
        return {
            'id': patient.id,
            'name': decrypt_value(patient.name),
            'phone': decrypt_value(patient.phone),
            'email': decrypt_value(patient.email),
            'address': decrypt_value(patient.address),
            'state': decrypt_value(patient.state),
            'postal_code': decrypt_value(patient.postal_code),
            'insurance_name': decrypt_value(patient.insurance_name),
            'insurance_no': decrypt_value(patient.insurance_no),
            'date_of_birth': patient.date_of_birth.strftime('%Y-%m-%d') if patient.date_of_birth else None,
            'clinic_id': patient.clinic_id,
            'created_at': patient.created_at.strftime('%Y-%m-%d %H:%M:%S') if patient.created_at else None
        }
    except Exception as e:
        print(f"Decryption Error: {str(e)}")
        return {'error': f'Decryption failed: {str(e)}'}

def decrypt_patient_auto(patient):
    """Automatically choose the correct decryption method based on data format."""
    def needs_enc_decryption(value):
        return isinstance(value, str) and value.startswith("ENC::")

    if (
        needs_enc_decryption(patient.name)
        or needs_enc_decryption(patient.phone)
        or needs_enc_decryption(patient.email)
        or needs_enc_decryption(patient.address)
        or needs_enc_decryption(patient.state)
        or needs_enc_decryption(patient.postal_code)
        or needs_enc_decryption(patient.insurance_name)
        or needs_enc_decryption(patient.insurance_no)
    ):
        return decrypt_patient_enc(patient)
    else:
        return decrypt_patient(patient)

def decrypt_patient(patient):
    """Decrypt patient data for response."""
    try:
        return {
            'id': patient.id,
            'name': cipher.decrypt(patient.name) if patient.name else None,
            'phone': cipher.decrypt(patient.phone) if patient.phone else None,
            'email': cipher.decrypt(patient.email) if patient.email else None,  # ✅ FIXED HERE
            'address': cipher.decrypt(patient.address) if patient.address else None,
            'state': cipher.decrypt(patient.state) if patient.state else None,
            'postal_code': cipher.decrypt(patient.postal_code) if patient.postal_code else None,
            'insurance_name': cipher.decrypt(patient.insurance_name) if patient.insurance_name else None,
            'insurance_no': cipher.decrypt(patient.insurance_no) if patient.insurance_no else None,
            'date_of_birth': patient.date_of_birth.strftime('%Y-%m-%d') if patient.date_of_birth else None,
            'clinic_id': patient.clinic_id,
            'created_at': patient.created_at.strftime('%Y-%m-%d %H:%M:%S') if patient.created_at else None
        }
    except Exception as e:
        print(f"Decryption Error: {str(e)}")  # Log issue
        return {'error': f'Decryption failed: {str(e)}'}

def encrypt_value(value):
    """Encrypt a string using AES-256-CBC and return in 'ENC::Base64' format."""
    if not value:
        return None

    # Convert value to bytes
    value_bytes = value.encode()

    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_value = padder.update(value_bytes) + padder.finalize()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_value = encryptor.update(padded_value) + encryptor.finalize()

    # Convert to Base64 and add ENC:: prefix
    encrypted_b64 = base64.b64encode(encrypted_value).decode()
    return f"ENC::{encrypted_b64}"

@patient.route('/patient/add', methods=['POST'])
@validate_api_key
def add_patient_contact():
    """🆕 Add patient with same encryption logic as /patient"""
    data = request.get_json()

    required_fields = ['name', 'date_of_birth', 'clinic_id']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # ✅ Validate clinic existence
    clinic = Clinic.query.get(data['clinic_id'])
    if not clinic:
        return jsonify({'error': 'Clinic not found'}), 404

    # ✅ Validate and parse DOB
    date_of_birth = parse_date(data['date_of_birth'])
    if not date_of_birth:
        return jsonify({'error': 'Invalid date format (YYYY-MM-DD required).'}), 400

    # ✅ Encrypt email if provided
    encrypted_email = None
    if 'email' in data and data['email']:
        encrypted_email = cipher.encrypt(data['email'])

        # Check if encrypted email already exists
        if Patient.query.filter_by(email=encrypted_email).first():
            return jsonify({'error': 'Email already exists'}), 400

    try:
        # ✅ Use raw name/phone (NOT encrypted — to match /patient logic)
        new_patient = Patient(
            name=data['name'],
            phone=data.get('phone'),
            email=encrypted_email,
            address=data.get('address'),
            state=data.get('state'),
            postal_code=data.get('postal_code'),
            insurance_name=data.get('insurance_name'),
            insurance_no=data.get('insurance_no'),
            date_of_birth=date_of_birth,
            clinic_id=data['clinic_id']
        )

        db.session.add(new_patient)
        db.session.commit()

        return jsonify({
            "patient_id": new_patient.id,
            "message": "Patient created successfully"
        }), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

@patient.route('/patient/by-phone', methods=['GET'])
@validate_api_key
def get_patient_by_phone():
    phone = request.args.get('phone')
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    def decrypt_patient_auto(patient):
        """Automatically choose the correct decryption method based on data format."""
        def needs_enc_decryption(value):
            return isinstance(value, str) and value.startswith("ENC::")

        if (
            needs_enc_decryption(patient.name)
            or needs_enc_decryption(patient.phone)
            or needs_enc_decryption(patient.email)
            or needs_enc_decryption(patient.address)
            or needs_enc_decryption(patient.state)
            or needs_enc_decryption(patient.postal_code)
            or needs_enc_decryption(patient.insurance_name)
            or needs_enc_decryption(patient.insurance_no)
        ):
            return decrypt_patient_enc(patient)
        else:
            return decrypt_patient(patient)

    def normalize_phone(value):
        """Ensure phone starts with + and is stripped clean."""
        if not value:
            return ""
        value = value.strip()
        return value if value.startswith("+") else f"+{value}"

    try:
        print(f"\n🔍 Incoming search for phone: [{phone}]")
        normalized_input = normalize_phone(phone)
        print(f"🔧 Normalized search phone: [{normalized_input}]")

        patients = Patient.query.filter(Patient.phone.isnot(None)).all()
        print(f"📦 Found {len(patients)} patients")

        for patient in patients:
            try:
                decrypted = decrypt_patient_auto(patient)
                decrypted_phone = normalize_phone(decrypted.get('phone'))

                print(f"🔍 Checking ID {patient.id} | Decrypted normalized phone: [{decrypted_phone}]")

                if decrypted_phone == normalized_input:
                    print(f"✅ Match found with patient ID {patient.id}")
                    return jsonify(decrypted), 200

            except Exception as e:
                print(f"⚠️ Error decrypting patient ID {patient.id}: {e}")
                continue

        print("❌ No match found")
        return jsonify({'error': 'Patient not found'}), 404

    except Exception as e:
        print(f"🔥 Server error: {e}")
        return jsonify({'error': 'Server error', 'details': str(e)}), 500

# CREATE PATIENT
@patient.route('/patient', methods=['POST'])
# @validate_api_key
# @log_api_access
# @validate_bearer_token
def create_patient():
    data = request.get_json()
    
    required_fields = ['name', 'date_of_birth', 'clinic_id']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Validate clinic existence
    clinic = Clinic.query.get(data['clinic_id'])
    if not clinic:
        return jsonify({'error': 'Clinic not found'}), 404

    # Validate date_of_birth
    date_of_birth = parse_date(data['date_of_birth'])
    if not date_of_birth:
        return jsonify({'error': 'Invalid date format (YYYY-MM-DD required).'}), 400

    # Encrypt email if provided
    encrypted_email = None
    if 'email' in data and data['email']:
        encrypted_email = cipher.encrypt(data['email'])  # ✅ FIXED HERE

        # Check if encrypted email already exists
        if Patient.query.filter_by(email=encrypted_email).first():
            return jsonify({'error': 'Email already exists'}), 400

    try:
        new_patient = Patient(
            name=data['name'],
            phone=data.get('phone'),
            email=data.get('email'),  # Store encrypted email
            address=data.get('address'),
            state=data.get('state'),
            postal_code=data.get('postal_code'),
            insurance_name=data.get('insurance_name'),
            insurance_no=data.get('insurance_no'),
            date_of_birth=date_of_birth,
            clinic_id=data['clinic_id']
        )
        db.session.add(new_patient)
        db.session.commit()
        return jsonify({
            "patient_id": new_patient.id,
            "message": "Patient created successfully"
        }), 201  # Return patient ID only

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Database error', 'details': str(e)}), 500
    

# Utility function to automatically choose the correct decryption method
def decrypt_patient_auto(patient):
    """Automatically choose the correct decryption method based on data format."""
    def needs_enc_decryption(value):
        return isinstance(value, str) and value.startswith("ENC::")

    if (
        needs_enc_decryption(patient.name)
        or needs_enc_decryption(patient.phone)
        or needs_enc_decryption(patient.email)
        or needs_enc_decryption(patient.address)
        or needs_enc_decryption(patient.state)
        or needs_enc_decryption(patient.postal_code)
        or needs_enc_decryption(patient.insurance_name)
        or needs_enc_decryption(patient.insurance_no)
    ):
        return decrypt_patient_enc(patient)
    else:
        return decrypt_patient(patient)


@patient.route('/patient/<int:id>', methods=['GET'])
@validate_api_key
@validate_bearer_token
@log_api_access
def get_patient(id):
    patient = Patient.query.get(id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404

    # Use the same auto decryption logic here
    return jsonify(decrypt_patient_auto(patient)), 200


# UPDATE PATIENT
@patient.route('/patient/<int:id>', methods=['PUT'])
@validate_api_key
@validate_bearer_token
@log_api_access
def update_patient(id):
    patient = Patient.query.get(id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404

    data = request.get_json()
    
    if 'name' in data:
        patient.name = data['name']
    if 'phone' in data:
        patient.phone = cipher.encrypt(data['phone'])
    if 'email' in data:
        patient.email = cipher.encrypt(data['email'])
    if 'insurance_no' in data:
        patient.insurance_no = cipher.encrypt(data['insurance_no'])
    if 'address' in data:
        patient.address = data['address']
    if 'state' in data:
        patient.state = data['state']
    if 'postal_code' in data:
        patient.postal_code = data['postal_code']
    if 'insurance_name' in data:
        patient.insurance_name = data['insurance_name']
    
    # Validate & update date_of_birth
    if 'date_of_birth' in data:
        date_of_birth = parse_date(data['date_of_birth'])
        if not date_of_birth:
            return jsonify({'error': 'Invalid date format (YYYY-MM-DD required).'}), 400
        patient.date_of_birth = date_of_birth

    try:
        db.session.commit()
        return jsonify(decrypt_patient(patient)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

# DELETE PATIENT
@patient.route('/patient/<int:id>', methods=['DELETE'])
@validate_api_key
@validate_bearer_token
@log_api_access
def delete_patient(id):
    patient = Patient.query.get(id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404

    db.session.delete(patient)
    db.session.commit()

    return jsonify({'message': 'Patient deleted successfully'}), 200

@patient.route('/patient', methods=['GET'])
@validate_api_key
@log_api_access
def get_all_patients():
    def decrypt_patient_auto(patient):
        """Automatically choose the correct decryption method based on data format."""
        def needs_enc_decryption(value):
            return isinstance(value, str) and value.startswith("ENC::")

        if (
            needs_enc_decryption(patient.name)
            or needs_enc_decryption(patient.phone)
            or needs_enc_decryption(patient.email)
            or needs_enc_decryption(patient.address)
            or needs_enc_decryption(patient.state)
            or needs_enc_decryption(patient.postal_code)
            or needs_enc_decryption(patient.insurance_name)
            or needs_enc_decryption(patient.insurance_no)
        ):
            return decrypt_patient_enc(patient)
        else:
            return decrypt_patient(patient)

    patients = Patient.query.order_by(Patient.created_at.desc()).all()  # 🔹 Sorted by created_at DESC
    return jsonify([decrypt_patient_auto(p) for p in patients]), 200

from sqlalchemy import text
from sqlalchemy import func, distinct
import phonenumbers

@patient.route('/patient/with-phone', methods=['GET'])
@validate_api_key
@log_api_access
def get_patients_with_phone():
    """Retrieve only patients who have a phone number (unique phone numbers only) - Optimized for Speed"""
    
    def decrypt_patient_auto(patient):
        """Automatically choose the correct decryption method based on data format."""
        def needs_enc_decryption(value):
            return isinstance(value, str) and value.startswith("ENC::")

        if any(needs_enc_decryption(getattr(patient, field, "")) for field in [
            "name", "phone", "email", "address", "state", 
            "postal_code", "insurance_name", "insurance_no"
        ]):
            return decrypt_patient_enc(patient)
        return decrypt_patient(patient)

    # 🔹 Optimize Query: Fetch only latest record for each unique phone number
    subquery = db.session.query(
        Patient.phone, 
        func.max(Patient.created_at).label("latest_created_at")  # Get latest entry per phone
    ).filter(Patient.phone.isnot(None), Patient.phone != "").group_by(Patient.phone).subquery()

    patients = db.session.query(Patient).join(
        subquery, 
        (Patient.phone == subquery.c.phone) & (Patient.created_at == subquery.c.latest_created_at)
    ).yield_per(100)  # ✅ Stream data for performance

    unique_patients = {}
    
    for patient in patients:
        try:
            # 🔹 Standardize phone format to ensure proper duplicate detection
            parsed_number = phonenumbers.parse(patient.phone, "US")  
            standardized_phone = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException:
            standardized_phone = patient.phone  # Keep the original if invalid

        # ✅ Store only one record per unique phone number
        unique_patients.setdefault(standardized_phone, patient)

    return jsonify([decrypt_patient_auto(p) for p in unique_patients.values()]), 200

from flask import jsonify
from sqlalchemy import text
import phonenumbers
from flask import jsonify
from sqlalchemy import text
import phonenumbers
# @patient.route('/patient/by-phone/<string:phone>', methods=['GET'])
# def get_patient_by_phone(phone):
#     """🔄 Search for a patient by phone number with automatic decryption detection and improved matching."""

#     def decrypt_patient_auto(patient):
#         """Automatically decrypt fields in the patient record if they appear encrypted."""
#         def attempt_decryption(value):
#             """Try to decrypt the value and return original if decryption fails."""
#             try:
#                 return decrypt_value(value)
#             except Exception:
#                 return value  # Return original value if decryption fails

#         patient.name = attempt_decryption(patient.name)
#         patient.phone = attempt_decryption(patient.phone)
#         patient.email = attempt_decryption(patient.email)
#         patient.address = attempt_decryption(patient.address)
#         patient.state = attempt_decryption(patient.state)
#         patient.postal_code = attempt_decryption(patient.postal_code)
#         patient.insurance_name = attempt_decryption(patient.insurance_name)
#         patient.insurance_no = attempt_decryption(patient.insurance_no)

#         return patient  # Return decrypted patient object

#     def normalize_phone(phone):
#         """Convert a phone number into a standard E.164 format."""
#         try:
#             parsed_number = phonenumbers.parse(phone, "US")
#             return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)  # +1XXXXXXXXXX
#         except phonenumbers.NumberParseException:
#             return phone  # Return original if parsing fails

#     # 🔥 Normalize the input phone number
#     normalized_input = normalize_phone(phone)
#     print(f"🔍 Searching for phone: {phone} (Normalized: {normalized_input})")

#     try:
#         # ✅ Fetch all patients (ID and phone) from the database
#         patients = db.session.execute(text("SELECT id, phone FROM patients")).fetchall()

#         matched_patient = None
#         stored_numbers_debug = []

#         for patient in patients:
#             try:
#                 stored_phone = patient.phone  # Original stored phone number

#                 # ✅ Attempt decryption for all phone numbers (even if no "ENC::" prefix)
#                 try:
#                     decrypted_phone = decrypt_value(stored_phone)
#                     decrypted_phone = normalize_phone(decrypted_phone)  # Normalize after decryption
#                 except Exception:
#                     decrypted_phone = normalize_phone(stored_phone)  # Fallback to original phone

#                 stored_numbers_debug.append({"id": patient.id, "stored": stored_phone, "decrypted": decrypted_phone})

#                 # ✅ Check if the normalized numbers match
#                 if decrypted_phone == normalized_input:
#                     print(f"✅ Match found: {decrypted_phone} (Patient ID: {patient.id})")
#                     matched_patient = Patient.query.get(patient.id)
#                     matched_patient = decrypt_patient_auto(matched_patient)  # ✅ Auto decryption for full record
#                     break

#             except Exception as e:
#                 print(f"❌ Decryption Error for phone {patient.phone}: {e}")  # Log error but continue

#         # 🔍 Debugging: Print all stored phone numbers
#         print(f"📌 All Stored Phones: {stored_numbers_debug}")

#         if not matched_patient:
#             print(f"❌ No match found for {normalized_input} in stored patient records.")
#             return jsonify({'error': 'Patient not found'}), 404

#         return jsonify({
#             "id": matched_patient.id,
#             "name": matched_patient.name,
#             "phone": matched_patient.phone,
#             "email": matched_patient.email,
#             "address": matched_patient.address,
#             "state": matched_patient.state,
#             "postal_code": matched_patient.postal_code,
#             "insurance_name": matched_patient.insurance_name,
#             "insurance_no": matched_patient.insurance_no,
#         }), 200

#     except Exception as e:
#         return jsonify({"error": "Database error", "details": str(e)}), 500


def normalize_phone(phone):
        """Convert a phone number into a standard E.164 format."""
        try:
            parsed_number = phonenumbers.parse(phone, "US")
            return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)  # +1XXXXXXXXXX
        except phonenumbers.NumberParseException:
            return phone  # Return original if parsing fails


# @patient.route('/patient/get-by-phone', methods=['GET'])
# # @validate_api_key
# # @log_api_access
# def get_patient_by_phone():
#     phone = request.args.get('phone')
#     if not phone:
#         return jsonify({'error': 'Phone number is required'}), 400

#     try:
#         encrypted_phone = cipher.encrypt(phone)
#         patient = Patient.query.filter_by(phone=encrypted_phone).first()

#         if not patient:
#             return jsonify({'error': 'Patient not found'}), 404

#         # Use smart decryption
#         return jsonify(decrypt_patient_auto(patient)), 200

#     except Exception as e:
#         return jsonify({'error': 'Server error', 'details': str(e)}), 500


import logging

# Configure logging
logging.basicConfig(level=logging.INFO)  # Set logging level to INFO


# @patient.route('/patient/by-phone/<string:phone>', methods=['GET'])
# def get_patient_by_phone(phone):
#     logging.info(f"📞 Searching for phone: {phone}")

#     # Normalize input phone number
#     normalized_input = normalize_phone(phone)
#     logging.info(f"📌 Normalized input phone: {normalized_input}")

#     # ✅ Fetch only `id` and `phone` from the database to speed up initial query
#     patients = db.session.execute(text("SELECT id, phone FROM patients")).fetchall()

#     matched_patient_id = None

#     # Pre-check decrypted phone numbers
#     for patient in patients:
#         stored_phone = patient.phone

#         if stored_phone.startswith("ENC::"):
#             try:
#                 decrypted_phone = decrypt_value(stored_phone)
#                 decrypted_phone = normalize_phone(decrypted_phone)
#             except Exception as e:
#                 logging.error(f"❌ Decryption error for patient {patient.id}: {e}")
#                 continue  # Skip this record if decryption fails
#         else:
#             decrypted_phone = normalize_phone(stored_phone)

#         if decrypted_phone == normalized_input:
#             matched_patient_id = patient.id
#             logging.info(f"✅ Match found: Patient ID {matched_patient_id}")
#             break  # Exit loop immediately when a match is found

#     if not matched_patient_id:
#         logging.warning(f"❌ No match found for phone {normalized_input}")
#         return jsonify({'error': 'Patient not found'}), 404

#     # ✅ Fetch full patient details **only for the matched patient** (avoids loading all records)
#     matched_patient = Patient.query.get(matched_patient_id)
#     if not matched_patient:
#         return jsonify({'error': 'Patient not found'}), 404

#     # ✅ Apply decryption only for the found patient
#     matched_patient = decrypt_patient_auto(matched_patient)

#     response_data = {
#         "id": matched_patient.id,
#         "name": matched_patient.decrypted_name,
#         "phone": matched_patient.decrypted_phone,
#         "email": matched_patient.decrypted_email,
#         "address": matched_patient.decrypted_address,
#         "state": matched_patient.decrypted_state,
#         "postal_code": matched_patient.decrypted_postal_code,
#         "insurance_name": matched_patient.decrypted_insurance_name,
#         "insurance_no": matched_patient.decrypted_insurance_no,
#     }

#     logging.info(f"📤 Returning patient data: {response_data}")
#     return jsonify(response_data), 200



# # Allowed file extensions
# ALLOWED_EXTENSIONS = {'csv'}
# UPLOAD_FOLDER = 'uploads'
# if not os.path.exists(UPLOAD_FOLDER):
#     os.makedirs(UPLOAD_FOLDER)

# # Define Encryption Key (Must be 32 bytes for AES-256)
# SECRET_KEY = b'12345678901234567890123456789012'  # Replace with a secure key
# IV = b'1234567890123456'  # 16-byte IV for AES

# # Function to check if file is allowed
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# # Encryption Function (AES-256-CBC)
# def encrypt_value(value):
#     """Encrypt value using AES encryption with padding"""
#     try:
#         if value and isinstance(value, str):
#             value_bytes = value.encode()  # Convert string to bytes

#             # Apply PKCS7 padding
#             padder = padding.PKCS7(128).padder()
#             padded_value = padder.update(value_bytes) + padder.finalize()

#             # Create Cipher
#             cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(IV), backend=default_backend())
#             encryptor = cipher.encryptor()
#             encrypted_data = encryptor.update(padded_value) + encryptor.finalize()

#             # Encode encrypted data
#             return f"ENC::{base64.b64encode(encrypted_data).decode()}"
#         return value
#     except Exception as e:
#         print(f"Encryption Error: {str(e)}")
#         return None  # Return None in case of encryption failure

# # Function to Parse Date
# def parse_date(date_str):
#     """Convert date string to date object"""
#     if not date_str or pd.isna(date_str):
#         return None
#     try:
#         return datetime.strptime(date_str, "%m/%d/%Y").date()
#     except ValueError as e:
#         print(f"Skipping row due to invalid date format: {date_str} -> {str(e)}")
#         return None

# @patient.route('/patient/upload_csv', methods=['POST'])
# def upload_patient_csv():
#     """ Upload CSV file and insert encrypted data into the database """
#     try:
#         if 'file' not in request.files:
#             return jsonify({"error": "No file part"}), 400

#         file = request.files['file']
#         if file.filename == '' or not allowed_file(file.filename):
#             return jsonify({"error": "Invalid file type. Only CSV allowed"}), 400

#         filename = secure_filename(file.filename)
#         filepath = os.path.join(UPLOAD_FOLDER, filename)
#         file.save(filepath)

#         df = pd.read_csv(filepath, dtype=str).fillna('')  # Convert all values to string

#         required_columns = {"id", "name", "phone", "email", "address", "state", "postal_code",
#                             "insurance_name", "insurance_no", "date_of_birth", "clinic_id", "created_at"}

#         if not required_columns.issubset(df.columns):
#             return jsonify({"error": "CSV file is missing required columns"}), 400

#         patients_list = []
#         total_attempted = 0
#         total_inserted = 0

#         for index, row in df.iterrows():
#             total_attempted += 1
#             try:
#                 # Convert and encrypt fields
#                 patient = Patient(
#                     id=int(row["id"]) if row["id"].isdigit() else None,
#                     name=encrypt_value(row["name"]),
#                     phone=encrypt_value(row["phone"]),
#                     email=encrypt_value(row["email"]),
#                     address=encrypt_value(row["address"]),
#                     state=encrypt_value(row["state"]),
#                     postal_code=encrypt_value(row["postal_code"]),
#                     insurance_name=encrypt_value(row["insurance_name"]),
#                     insurance_no=encrypt_value(row["insurance_no"]),
#                     date_of_birth=parse_date(row["date_of_birth"]),
#                     clinic_id=int(row["clinic_id"]) if row["clinic_id"].isdigit() else None,
#                     created_at=datetime.utcnow()
#                 )

#                 # Ensure required fields are present
#                 if not patient.name or not patient.date_of_birth:
#                     print(f"Skipping row {index} due to missing required fields")
#                     continue

#                 patients_list.append(patient)
#                 total_inserted += 1

#             except Exception as e:
#                 print(f"Skipping row {index} due to error: {str(e)}")

#         if patients_list:
#             db.session.bulk_save_objects(patients_list)
#             db.session.commit()

#         return jsonify({
#             "message": "CSV data uploaded and encrypted successfully!",
#             "records_inserted": total_inserted,
#             "total_attempted": total_attempted
#         }), 201

#     except Exception as e:
#         db.session.rollback()
#         return jsonify({"error": "Failed to upload CSV", "details": str(e)}), 500
