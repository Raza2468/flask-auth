from datetime import datetime
from sqlalchemy import Column, Integer, String, Date, DateTime, ForeignKey, Enum
from app.extensions import db
from app.utils import AESCipher
import os
from dotenv import load_dotenv
from sqlalchemy import TIMESTAMP
from sqlalchemy.dialects.postgresql import ARRAY


load_dotenv()
cipher = AESCipher(key=os.getenv('ENCRYPTION_KEY', 'default_encryption_key'))


# Define ENUM types explicitly with names
status_enum = Enum('accepted', 'rejected', 'pending', name='clinic_team_status_enum')
role_status_enum = Enum('active', 'inactive', name='role_status_enum')
userStatus_enum = Enum('pending', 'accepted', 'rejected', name='userStatus_enum')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(255), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    reset_token = db.Column(db.String(255), nullable=True)
    password_verify_token = db.Column(db.Integer, nullable=True)
    verification_code = db.Column(db.String(255), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    clinic_role_id = db.Column(db.Integer, db.ForeignKey('clinic_roles.id'), nullable=True)
    # dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=True)
    dashboard_id = db.Column(ARRAY(db.Integer), nullable=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    user_image = db.Column(db.String(255), nullable=True)
    userStatus = db.Column(db.String(50), nullable=False, default='active')
    city = db.Column(db.String(255), nullable=True)
    first_login = db.Column(db.SmallInteger, nullable=False, default=0)
    hash_key = db.Column(db.Integer, nullable=False, default=0)
    hash_expiry = db.Column(db.Integer, nullable=False, default=0)
    address = db.Column(db.String(255), nullable=False, default='None')
    enable_2fa = db.Column(db.String(255), nullable=True, default='None')
    otp_secret = db.Column(db.String(32), nullable=False)
    otp_password = db.Column(db.String(32), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    timezone = db.Column(db.String(50), nullable=True, default='UTC')
    created_at = db.Column(TIMESTAMP, nullable=True, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, nullable=True, default=datetime.utcnow)
    deleted_at = db.Column(TIMESTAMP, nullable=True)
    otp_expiry = db.Column(db.Integer, nullable=True)  # This is the new field

    
     
    def get_id(self):
        return str(self.id)
    def is_authenticated(self):
        return self.is_active


class Clinic(db.Model):
    __tablename__ = 'clinics'  # Specify the table name if different from the class name

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)  # Assuming you have a User model
    clinic_name = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(255), nullable=False)
    state = db.Column(db.String(255), nullable=False)
    postal_code = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(255), nullable=False)
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    timestamp = db.Column(db.Integer, nullable=False)
    timezone = db.Column(db.String(255), nullable=True)
    # patients = db.relationship('patient', backref='clinic', lazy=True)

    def __init__(self, user_id, clinic_name, address, city, state, postal_code, phone, timestamp, timezone=None):
        self.user_id = user_id
        self.clinic_name = clinic_name
        self.address = address
        self.city = city
        self.state = state
        self.postal_code = postal_code
        self.phone = phone
        self.timestamp = timestamp
        self.timezone = timezone


class ClinicTeam(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    clinic_id = db.Column(db.BigInteger, nullable=False)
    user_id = db.Column(db.BigInteger, nullable=False)
    invitation_token = db.Column(db.String(255), nullable=False, default='None')
    status = db.Column(status_enum, nullable=False, default='pending')
    email = db.Column(db.String(255), nullable=False, default='None')
    clinic_role_id = db.Column(db.Integer, db.ForeignKey('clinic_roles.id'), nullable=False)  
    designation = db.Column(db.String(255), nullable=False, default='None')
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    invited_by_id = db.Column(db.Integer, nullable=False)
    token = db.Column(db.String(255), nullable=True)
    expiration = db.Column(TIMESTAMP, nullable=True)

    def __init__(self, user_id, email, clinic_role_id, designation, clinic_id, invited_by_id, status, invitation_token, first_name=None, last_name=None, address=None, phone=None):
        self.user_id = user_id
        self.email = email
        self.clinic_role_id = clinic_role_id
        self.designation = designation
        self.clinic_id = clinic_id
        self.invited_by_id = invited_by_id
        self.status = status
        self.invitation_token = invitation_token
        self.first_name = first_name
        self.last_name = last_name
        self.address = address
        self.phone = phone


class ClinicRoles(db.Model):
    __tablename__ = 'clinic_roles'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    clinic_id = db.Column(db.BigInteger, nullable=False)  # Assuming this is a foreign key reference to Clinics table
    role_name = db.Column(db.String(255), nullable=False)
    status = db.Column(role_status_enum, nullable=False, default='active')
    permissions = db.Column(db.JSON, nullable=False)  # List of permissions
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, clinic_id, role_name, permissions, status='active'):
        self.clinic_id = clinic_id
        self.role_name = role_name
        self.permissions = permissions
        self.status = status

    def to_dict(self):
        return {
            'id': self.id,
            'clinic_id': self.clinic_id,
            'role_name': self.role_name,
            'status': self.status,
            'permissions': self.permissions,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    permissions = db.Column(db.JSON, nullable=False)  # List of permissions
    status = db.Column(db.String(50), default='active')  # Add status field

    def __init__(self, name, permissions, status='active'):
        self.name = name
        self.permissions = permissions
        self.status = status


class Dashboard(db.Model):
    __tablename__ = 'dashboard'

    # user_id = db.Column(Integer, ForeignKey('user.id'), nullable=False)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    layout = db.Column(db.String(255), nullable=True)
    image = db.Column(db.String(255), nullable=True)
    dashboard_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, name, layout=None):
        self.name = name
        self.layout = layout    


# class ClinicProviders(db.Model):
#     __tablename__ = 'clinic_providers'

#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     first_name = db.Column(db.String(255), nullable=False)
#     last_name = db.Column(db.String(255), nullable=False)
#     email = db.Column(db.String(255), nullable=True)
#     phone = db.Column(db.String(255), nullable=True)
#     designation = db.Column(db.String(255), nullable=False)
#     clinic_id = db.Column(db.Integer, nullable=False)
#     created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
#     status = db.Column(db.SmallInteger, nullable=True, default=1)
#     tin = db.Column(db.String(255), nullable=True)
#     state_id = db.Column(db.String(255), nullable=True)
#     npi = db.Column(db.String(255), nullable=True)

#     def __init__(self, first_name, last_name, email, phone, designation, clinic_id, tin, state_id, npi=None):
#         self.first_name = cipher.encrypt(first_name)
#         self.last_name = cipher.encrypt(last_name)
#         self.email = cipher.encrypt(email)
#         self.phone = cipher.encrypt(phone)
#         self.designation = designation
#         self.clinic_id = clinic_id
#         self.tin = cipher.encrypt(tin)
#         self.state_id = cipher.encrypt(state_id)
#         self.npi = cipher.encrypt(npi) if npi else None

#     def to_dict(self):
#         return {
#             'id': self.id,
#             'first_name': cipher.decrypt(self.first_name),
#             'last_name': cipher.decrypt(self.last_name),
#             'email': cipher.decrypt(self.email),
#             'phone': cipher.decrypt(self.phone),
#             'designation': self.designation,
#             'clinic_id': self.clinic_id,
#             'created_at': self.created_at,
#             'status': self.status,
#             'tin': cipher.decrypt(self.tin),
#             'state_id': cipher.decrypt(self.state_id),
#             'npi': cipher.decrypt(self.npi) if self.npi else None
#         }



class AppointmentStatus(db.Model):
    __tablename__ = "appointment_statuses"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.BigInteger, nullable=False)  # Who created the status
    status = db.Column(db.String(50), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ClinicProviders(db.Model):
    __tablename__ = 'clinic_providers'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(255), nullable=True)
    designation = db.Column(db.String(255), nullable=False)
    clinic_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    status = db.Column(db.SmallInteger, nullable=True, default=1)
    tin = db.Column(db.String(255), nullable=True)
    state_id = db.Column(db.String(255), nullable=True)
    npi = db.Column(db.String(255), nullable=True)

    def __init__(self, first_name, last_name, email, phone, designation, clinic_id, tin, state_id, npi=None):
        self.first_name = self.safe_encrypt(first_name)
        self.last_name = self.safe_encrypt(last_name)
        self.email = self.safe_encrypt(email)
        self.phone = self.safe_encrypt(phone)
        self.designation = designation
        self.clinic_id = clinic_id
        self.tin = self.safe_encrypt(tin)
        self.state_id = self.safe_encrypt(state_id)
        self.npi = self.safe_encrypt(npi) if npi else None

    def to_dict(self):
        return {
            'id': self.id,
            'first_name': self.safe_decrypt(self.first_name),
            'last_name': self.safe_decrypt(self.last_name),
            'email': self.safe_decrypt(self.email),
            'phone': self.safe_decrypt(self.phone),
            'designation': self.designation,
            'clinic_id': self.clinic_id,
            'created_at': self.created_at,
            'status': self.status,
            'tin': self.safe_decrypt(self.tin),
            'state_id': self.safe_decrypt(self.state_id),
            'npi': self.safe_decrypt(self.npi) if self.npi else None
        }

    def safe_encrypt(self, value):
        """Encrypt only if value is not already encrypted."""
        if value and not self.is_encrypted(value):
            return cipher.encrypt(value)
        return value  # Return as is if already encrypted

    def safe_decrypt(self, value):
        """Decrypt only if value is encrypted."""
        if value and self.is_encrypted(value):
            return cipher.decrypt(value)
        return value  # Return as is if already decrypted

    def is_encrypted(self, value):
        """Check if a value is encrypted by looking for encryption patterns (adjust based on your encryption method)."""
        return value.startswith("ENC(") and value.endswith(")")


class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    system_name = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ClinicLocation(db.Model):
    __tablename__ = 'clinic_locations'

    id = db.Column(db.Integer, primary_key=True)
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinics.id'), nullable=False)
    location_name = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(100), nullable=True)
    postal_code = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Automatically set on creation

    clinic = db.relationship('Clinic', backref=db.backref('locations', lazy=True))

    def __init__(self, clinic_id, location_name, address, city, state, postal_code, phone, email):
        self.clinic_id = clinic_id
        self.location_name = location_name
        self.address = address
        self.city = city
        self.state = state
        self.postal_code = postal_code
        self.phone = phone
        self.email = email


class ClinicRoom(db.Model):
    __tablename__ = 'clinic_rooms'

    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey('clinic_locations.id'), nullable=False)
    room_name = db.Column(db.String(255), nullable=False)
    capacity = db.Column(db.Integer, nullable=True)  # Optional: Room capacity
    status = db.Column(db.String(50), default="available")  # e.g., available, occupied, maintenance
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    location = db.relationship('ClinicLocation', backref=db.backref('rooms', lazy=True))

    def __init__(self, location_id, room_name, capacity, status):
        self.location_id = location_id
        self.room_name = room_name
        self.capacity = capacity
        self.status = status


class Patient(db.Model):
    __tablename__ = 'patients'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    phone = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True)
    address = Column(String(255), nullable=True)
    state = Column(String(100), nullable=True)
    postal_code = Column(String(100), nullable=True)
    insurance_name = Column(String(255), nullable=True)
    insurance_no = Column(String(255), nullable=True)
    date_of_birth = Column(Date, nullable=False)
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if key in ('name', 'phone', 'email', 'insurance_no', 'address', 'state', 'postal_code', 'insurance_name') and value:
               setattr(self, key, cipher.encrypt(value))
            elif key == 'date_of_birth' and value:
               setattr(self, key, value)   # Encrypt date_of_birth
            else:
               setattr(self, key, value)


    @property
    def decrypted_phone(self):
        return cipher.decrypt(self.phone)
    
    @property
    def decrypted_name(self):
        return cipher.decrypt(self.name)

    @property
    def decrypted_email(self):
        return cipher.decrypt(self.email)

    @property
    def decrypted_insurance_no(self):
        return cipher.decrypt(self.insurance_no)
    
    @property
    def decrypted_date_of_birth(self):
        return self.date_of_birth.strftime('%Y-%m-%d')
    
    @property
    def decrypted_address(self):
        return cipher.decrypt(self.address)
    
    @property
    def decrypted_state(self):
        return cipher.decrypt(self.state)
    
    @property
    def decrypted_postal_code(self):
        return cipher.decrypt(self.postal_code)
    
    @property
    def decrypted_insurance_name(self):
        return cipher.decrypt(self.insurance_name)
    
    @property
    def decrypted_date_of_birth(self):
        return cipher.decrypt(self.date_of_birth)

# from datetime import datetime, date
# from sqlalchemy import Column, Integer, String, Date, DateTime, ForeignKey
# from sqlalchemy.orm import validates

# class Patient(db.Model):
#     __tablename__ = 'patients'

#     id = Column(Integer, primary_key=True, autoincrement=True)
#     name = Column(String(100), nullable=False)
#     phone = Column(String(255), nullable=True)
#     email = Column(String(255), nullable=True)
#     address = Column(String(255), nullable=True)
#     state = Column(String(100), nullable=True)
#     postal_code = Column(String(100), nullable=True)
#     insurance_name = Column(String(255), nullable=True)
#     insurance_no = Column(String(255), nullable=True)
#     date_of_birth = Column(Date, nullable=False)
#     clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
#     created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

#     def __init__(self, **kwargs):
#         for key, value in kwargs.items():
#             if key in ('name', 'phone', 'email', 'insurance_no', 'address', 'state', 'postal_code', 'insurance_name') and value:
#                 setattr(self, key, cipher.encrypt(value) if not self.is_encrypted(value) else value)
#             else:
#                 setattr(self, key, value)

#     @staticmethod
#     def is_encrypted(value):
#         """Check if the value is already encrypted (Example: Modify this based on your encryption logic)"""
#         return value.startswith("ENC::") if isinstance(value, str) else False

#     def decrypt_value(self, value):
#         """Decrypt only if the value is encrypted"""
#         if value and self.is_encrypted(value):
#             return cipher.decrypt(value)
#         return value

#     @property
#     def decrypted_phone(self):
#         return self.decrypt_value(self.phone)

#     @property
#     def decrypted_name(self):
#         return self.decrypt_value(self.name)

#     @property
#     def decrypted_email(self):
#         return self.decrypt_value(self.email)

#     @property
#     def decrypted_insurance_no(self):
#         return self.decrypt_value(self.insurance_no)

#     @property
#     def decrypted_date_of_birth(self):
#         return self.date_of_birth.strftime('%Y-%m-%d') if self.date_of_birth else None

#     @property
#     def decrypted_address(self):
#         return self.decrypt_value(self.address)

#     @property
#     def decrypted_state(self):
#         return self.decrypt_value(self.state)

#     @property
#     def decrypted_postal_code(self):
#         return self.decrypt_value(self.postal_code)

#     @property
#     def decrypted_insurance_name(self):
#         return self.decrypt_value(self.insurance_name)


class Insurance(db.Model):
    __tablename__ = 'insurances'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Auto-increment primary key
    policy_number = db.Column(db.String(100), unique=True, nullable=False)
    provider_name = db.Column(db.String(100), nullable=False)
    coverage_amount = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinics.id'), nullable=False)

    def __init__(self, policy_number, provider_name, coverage_amount, start_date, end_date, is_active, patient_id, clinic_id):
        self.policy_number = policy_number
        self.provider_name = provider_name
        self.coverage_amount = coverage_amount
        self.start_date = start_date
        self.end_date = end_date
        self.is_active = is_active
        self.patient_id = patient_id
        self.clinic_id = clinic_id


class InsuranceCompany(db.Model):
    __tablename__ = 'insurance_companies'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    short_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(500), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    website = db.Column(db.String(255), nullable=True)
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinics.id'), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "clinic_id": self.clinic_id,
            "name": self.name,
            "short_name": self.short_name,
            "address": self.address,
            "phone": self.phone,
            "email": self.email,
            "website": self.website
        }


class APILog(db.Model):
    __tablename__ = 'api_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    system_name = db.Column(db.String(255), nullable=True)
    user_email = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(255), nullable=True)
    app_name = db.Column(db.String(255), nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)


class Procedure(db.Model):
    __tablename__ = 'procedures'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    code = db.Column(db.String(20), nullable=True)
    procedure_name = db.Column(db.String(255), nullable=False)
    cost = db.Column(db.Numeric(10, 2), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Procedure {self.procedure_name}>"
    

class ProcedureOption(db.Model):
    __tablename__ = 'procedure_options'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    procedure_id = db.Column(db.Integer, nullable=False)
    option_name = db.Column(db.String(40), nullable=False)
    additional_cost = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<ProcedureOption {self.option_name}>"
    
    
class ProcedureLog(db.Model):
    __tablename__ = 'procedure_logs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    procedure_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.BigInteger, nullable=False)
    clinic_id = db.Column(db.BigInteger, nullable=False)
    change_description = db.Column(db.String(255), nullable=False)
    log_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.TIMESTAMP, default=db.func.current_timestamp(), nullable=False)



class ProcedureStep(db.Model):
    __tablename__ = 'procedure_steps'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    procedure_id = db.Column(db.Integer, nullable=False)
    step_number = db.Column(db.Integer, nullable=False)
    step_name = db.Column(db.String(255), nullable=False)
    step_description = db.Column(db.Text, nullable=True)
    step_price = db.Column(db.Numeric(10, 2), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<ProcedureStep(id={self.id}, step_name='{self.step_name}', procedure_id='{self.procedure_id}')>"


class Service(db.Model):
    __tablename__ = 'services'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    clinic_id = db.Column(db.BigInteger, nullable=False)
    category_id = db.Column(db.BigInteger, nullable=True)
    user_id = db.Column(db.BigInteger, nullable=False)
    treatment_area_id = db.Column(db.BigInteger, nullable=True)
    treatment_area2_id = db.Column(db.Integer, nullable=True)
    code = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    office_code = db.Column(db.String(255), nullable=False)
    image = db.Column(db.String(255), nullable=True)
    amount_il = db.Column(db.Float, nullable=False)
    amount_wi = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())


    def __repr__(self):
        return f'<Service {self.code}>'


class ServiceCategory(db.Model):
    __tablename__ = 'service_categories'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category = db.Column(db.String(255), nullable=False)
    clinic_id = db.Column(db.BigInteger, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<ServiceCategory {self.category}>'


class ServiceTreatmentArea(db.Model):
    __tablename__ = 'service_treatment_areas'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    clinic_id = db.Column(db.BigInteger, nullable=False)
    treatment_area = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<ServiceTreatmentArea {self.treatment_area}>'


class TreatmentOption(db.Model):
    __tablename__ = 'treatment_options'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    treatment_id = db.Column(db.BigInteger, nullable=False)
    option_name = db.Column(db.String(255), nullable=False)
    option_type = db.Column(db.String(255), nullable=True)
    status = db.Column(db.SmallInteger, nullable=False, default=1)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<TreatmentOption {self.option_name}>'


class TreatmentOptionValue(db.Model):
    __tablename__ = 'treatment_option_values'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    option_id = db.Column(db.BigInteger, nullable=False)
    value = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<TreatmentOptionValue {self.value}>'


class StaffLocation(db.Model):
    __tablename__ = 'staff_locations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    clinic_id = db.Column(db.BigInteger, nullable=False)
    location_id = db.Column(db.BigInteger, nullable=False)
    staff_id = db.Column(db.BigInteger, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PreAuthStatus(db.Model):

    __tablename__ = 'pre_auth_statuses'

    # Column definitions
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)  # using Boolean instead of tinyint(4)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<PreAuthStatus {self.id}, User: {self.user_id}, Status: {self.status}>'



class LabCaseStatus(db.Model):
    __tablename__ = 'lab_case_status'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    status_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.Enum('active', 'inactive', name='status_enum'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<LabCaseStatus(id={self.id}, status_name='{self.status_name}', status='{self.status}', user_id={self.user_id})>"


class BatchCaseStatus(db.Model):
    __tablename__ = 'batch_statuses'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    status_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.Enum('active', 'inactive', name='status_enum'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<BatchCaseStatus(id={self.id}, status_name='{self.status_name}', status='{self.status}', user_id={self.user_id})>"
    




class InsurancePayer(db.Model):
    __tablename__ = "insurance_payers"

    id = db.Column(db.Integer, primary_key=True)
    payer_code = db.Column(db.String(50), unique=True, nullable=False)
    payer_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)





# venv\Scripts\activate

# flask db update
# flask db migrate -m "Added new user routes and updated models"

# flask dn create
# 1. Check the Current Migration State
# flask db current
# flask db stamp head
# 2. Stamp the Database to the Latest Migration
# flask db migrate -m "Create role table"
# 3. Create and Apply the Migration
# flask db migrate -m "Create role table"
# flask db upgrade
# pip install -r requirements.txt


# flask db migrate -m "Fix auto-increment for user.id"
# flask db upgrade


# flask db current
#  flask db stamp head
# flask db migrate -m "Added new user routes and updated models"
# flask db upgrade


# Mannualy add schema
# flask db migrate -m "Added new user routes and updated models"
# flask db upgrade

# manual add new colmun in table
# flask db migrate -m "Added new user routes and updated models"
# flask db upgrade

# Delete Database (for Development) and Recreate it

# flask db init      # Initialize migrations if not done already
# flask db migrate -m "Initial migration"
# flask db upgrade   # Apply the migration to create the tables

# flask db migrate -m "Added Insurance table"

# python -m venv myenv
# .\myenv\Scripts\Activate.ps1
