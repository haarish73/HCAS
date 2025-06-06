# # Directory Structure
# # healthcare_app/
# # ├── app.py
# # ├── templates/
# # │   ├── index.html
# # │   ├── login.html
# # │   ├── register.html
# # │   ├── doctor_register.html
# # │   ├── doctor_login.html
# # │   ├── dashboard.html
# # │   ├── doctor_dashboard.html
# # │   └── ...
# # ├── static/
# # │   ├── css/
# # │   │   └── style.css
# # └── config.py

# # app.py
# from flask import Flask, render_template, redirect, url_for, request, session, flash
# from flask_wtf import CSRFProtect
# from pymongo import MongoClient
# from werkzeug.security import generate_password_hash, check_password_hash
# from bson.objectid import ObjectId
# from datetime import datetime
# import os


# app = Flask(__name__)
# app.config.from_pyfile('config.py')
# app.config['SESSION_COOKIE_SECURE'] = True
# app.config['SESSION_COOKIE_HTTPONLY'] = True
# app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# app.secret_key = app.config['SECRET_KEY']
# csrf = CSRFProtect(app)

# client = MongoClient(app.config['MONGO_URI'])

# db = client["healthcare_appointments"]
# appointments_collection = db["appointments"]
# users_collection = db["users"]
# doctors_collection = db["doctors"]

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/register', methods=['GET', 'POST'])
# @csrf.exempt
# def register():
#     if request.method == 'POST':
#         users = db.users
#         existing_user = users.find_one({'email': request.form['email']})
#         if existing_user:
#             flash('User already exists!')
#             return redirect(url_for('register'))

#         hashpass = generate_password_hash(request.form['password'])
#         users.insert_one({
#             'name': request.form['name'],
#             'email': request.form['email'],
#             'password': hashpass,
#             'role': 'patient',
#             'profile': {
#                 'age': request.form['age'],
#                 'gender': request.form['gender'],
#                 'contact': request.form['contact'],
#                 'history': request.form['history']
#             }
#         })
#         flash('Registration successful!')
#         return redirect(url_for('login'))

#     return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# @csrf.exempt
# def login():
#     if request.method == 'POST':
#         users = db.users
#         user = users.find_one({'email': request.form['email']})

#         if user and check_password_hash(user['password'], request.form['password']):
#             session['email'] = user['email']
#             session['role'] = user['role']
#             flash('Login successful!')
#             return redirect(url_for('user_dashboard')) if user['role'] == 'patient' else redirect(url_for('doctor_dashboard'))
#         else:
#             flash('Invalid login credentials')

#     return render_template('login.html')

# @app.route('/doctor/register', methods=['GET', 'POST'])
# @csrf.exempt
# def doctor_register():
#     if request.method == 'POST':
#         users = db.users
#         existing_user = users.find_one({'email': request.form['email']})
#         if existing_user:
#             flash('Doctor already exists!')
#             return redirect(url_for('doctor_register'))

#         hashpass = generate_password_hash(request.form['password'])
#         users.insert_one({
#             'name': request.form['name'],
#             'email': request.form['email'],
#             'password': hashpass,
#             'role': 'doctor',
#             'specialty': request.form['specialty'],
#             'qualification': request.form['qualification'],
#             'availability': []
#         })
#         flash('Doctor registration successful!')
#         return redirect(url_for('doctor_login'))

#     return render_template('doctor_register.html')

# @app.route('/doctor/login', methods=['GET', 'POST'])
# @csrf.exempt
# def doctor_login():
#     if request.method == 'POST':
#         users = db.users
#         user = users.find_one({'email': request.form['email'], 'role': 'doctor'})

#         if user and check_password_hash(user['password'], request.form['password']):
#             session['email'] = user['email']
#             session['role'] = 'doctor'
#             flash('Doctor login successful!')
#             return redirect(url_for('doctor_dashboard'))
#         else:
#             flash('Invalid login credentials')

#     return render_template('doctor_login.html')

# @app.route('/dashboard')
# def user_dashboard():
#     if 'email' not in session or session.get('role') != 'patient':
#         return redirect(url_for('login'))

#     user = db.users.find_one({'email': session['email']})
#     doctors = list(db.users.find({'role': 'doctor'}))
#     appointments = list(db.appointments.find({'patient_email': session['email']}))
#     return render_template('user_dashboard.html', user=user, doctors=doctors, appointments=appointments)

# @app.route('/book_appointment/<doctor_email>', methods=['POST'])
# @csrf.exempt
# def book_appointment(doctor_email):
#     if 'email' not in session or session.get('role') != 'patient':
#         return redirect(url_for('login'))

#     appointment = {
#         'patient_email': session['email'],
#         'doctor_email': doctor_email,
#         'date': request.form['date'],
#         'time': request.form['time'],
#         'reason': request.form['reason'],
#         'status': 'pending',
#         'created_at': datetime.utcnow()
#     }
#     db.appointments.insert_one(appointment)
#     flash('Appointment request sent!')
#     return redirect(url_for('dashboard'))

# @app.route('/doctor/dashboard')
# def doctor_dashboard():
#     if 'email' not in session or session.get('role') != 'doctor':
#         return redirect(url_for('doctor_login'))

#     user = db.users.find_one({'email': session['email']})
#     appointments = list(db.appointments.find({'doctor_email': session['email']}))
#     return render_template('doctor_dashboard.html', user=user, appointments=appointments)

# @app.route('/update_appointment/<appointment_id>/<status>')
# @csrf.exempt
# def update_appointment(appointment_id, status):
#     if 'email' not in session or session.get('role') != 'doctor':
#         return redirect(url_for('doctor_login'))

#     db.appointments.update_one({'_id': ObjectId(appointment_id)}, {'$set': {'status': status}})
#     flash(f'Appointment {status}!')
#     return redirect(url_for('doctor_dashboard'))

# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)

# # Note:
# # ✅ User Authentication and Sessions are managed via Flask sessions.
# # ✅ Passwords are hashed using Werkzeug.
# # ✅ CSRF Protection is enabled via Flask-WTF's CSRFProtect.
# # ❌ Google Login and Deployment setup are excluded as per the request.

# # HTML templates and advanced CSS to be added separately.




#_____________________________________________________________________________________________________________
# from flask import Flask, render_template, redirect, url_for, request, session, flash
# from flask_wtf import CSRFProtect
# from pymongo import MongoClient
# from werkzeug.security import generate_password_hash, check_password_hash
# from bson.objectid import ObjectId
# from datetime import datetime
# import os

# # Flask App Config
# app = Flask(__name__)
# app.config.from_pyfile('config.py')
# app.secret_key = app.config['SECRET_KEY']

# # Secure Session Settings
# app.config['SESSION_COOKIE_SECURE'] = True
# app.config['SESSION_COOKIE_HTTPONLY'] = True
# app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# # CSRF
# csrf = CSRFProtect(app)

# # MongoDB Setup
# client = MongoClient(app.config['MONGO_URI'])
# db = client["healthcare_appointments"]
# appointments_collection = db["appointments"]
# users_collection = db["users"]

# # Home Page
# @app.route('/')
# def home():
#     return render_template('index.html')

# # Patient Registration
# @app.route('/register', methods=['GET', 'POST'])
# @csrf.exempt
# def register():
#     if request.method == 'POST':
#         existing_user = users_collection.find_one({'email': request.form['email']})
#         if existing_user:
#             flash('User already exists!')
#             return redirect(url_for('register'))

#         hashed_pw = generate_password_hash(request.form['password'])
#         users_collection.insert_one({
#             'name': request.form['name'],
#             'email': request.form['email'],
#             'password': hashed_pw,
#             'role': 'patient',
#             'profile': {
#                 'age': request.form['age'],
#                 'gender': request.form['gender'],
#                 'contact': request.form['contact'],
#                 'history': request.form['history']
#             }
#         })
#         flash('Registration successful!')
#         return redirect(url_for('login'))
#     return render_template('register.html')

# # Doctor Registration
# @app.route('/doctor/register', methods=['GET', 'POST'])
# @csrf.exempt
# def doctor_register():
#     if request.method == 'POST':
#         existing_user = users_collection.find_one({'email': request.form['email']})
#         if existing_user:
#             flash('Doctor already exists!')
#             return redirect(url_for('doctor_register'))

#         hashed_pw = generate_password_hash(request.form['password'])
#         users_collection.insert_one({
#             'name': request.form['name'],
#             'email': request.form['email'],
#             'password': hashed_pw,
#             'role': 'doctor',
#             'specialty': request.form['specialty'],
#             'qualification': request.form['qualification'],
#             'availability': []
#         })
#         flash('Doctor registration successful!')
#         return redirect(url_for('login'))
#     return render_template('doctor_register.html')

# # Login (both patient and doctor)
# @app.route('/login', methods=['GET', 'POST'])
# @csrf.exempt
# def login():
#     if request.method == 'POST':
#         user = users_collection.find_one({'email': request.form['email']})
#         if user and check_password_hash(user['password'], request.form['password']):
#             session['user_id'] = str(user['_id'])
#             session['email'] = user['email']
#             session['role'] = user['role']  # ✅ Correctly store role
#             flash('Login successful!')

#             if user['role'] == 'patient':
#                 return redirect(url_for('user_dashboard'))
#             elif user['role'] == 'doctor':
#                 return redirect(url_for('doctor_dashboard'))

#         else:
#             flash('Invalid login credentials')
#     return render_template('login.html')

# # Logout
# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('Logged out successfully.')
#     return redirect(url_for('login'))

# # Patient Dashboard
# @app.route('/dashboard')
# def user_dashboard():
#     if session.get('role') != 'patient':
#         flash('Unauthorized access.')
#         return redirect(url_for('login'))

#     user = users_collection.find_one({'email': session['email']})
#     doctors = list(users_collection.find({'role': 'doctor'}))
#     appointments = list(appointments_collection.find({'patient_email': session['email']}))
#     return render_template('user_dashboard.html', user=user, doctors=doctors, appointments=appointments)

# # Doctor Dashboard
# @app.route('/doctor/dashboard')
# def doctor_dashboard():
#     if session.get('role') != 'doctor':
#         flash('Unauthorized access.')
#         return redirect(url_for('login'))

#     user = users_collection.find_one({'email': session['email']})
#     appointments = list(appointments_collection.find({'doctor_email': session['email']}))
#     return render_template('doctor_dashboard.html', user=user, appointments=appointments)

# # Book Appointment (Patient)
# @app.route('/book_appointment/<doctor_email>', methods=['POST'])
# @csrf.exempt
# def book_appointment(doctor_email):
#     if session.get('role') != 'patient':
#         return redirect(url_for('login'))

#     appointment = {
#         'patient_email': session['email'],
#         'doctor_email': doctor_email,
#         'date': request.form['date'],
#         'time': request.form['time'],
#         'reason': request.form['reason'],
#         'status': 'pending',
#         'created_at': datetime.utcnow()
#     }
#     appointments_collection.insert_one(appointment)
#     flash('Appointment request sent!')
#     return redirect(url_for('user_dashboard'))

# # Doctor Accept/Reject Appointment
# @app.route('/update_appointment/<appointment_id>/<status>')
# @csrf.exempt
# def update_appointment(appointment_id, status):
#     if session.get('role') != 'doctor':
#         return redirect(url_for('login'))

#     appointments_collection.update_one(
#         {'_id': ObjectId(appointment_id)},
#         {'$set': {'status': status}}
#     )
#     flash(f'Appointment {status.capitalize()}!')
#     return redirect(url_for('doctor_dashboard'))

# # Doctor Login Shortcut
# @app.route('/doctor/login')
# def doctor_login():
#     return redirect(url_for('login'))

# # Run the App
# if __name__ == '__main__':
#     app.run(debug=True)



# updated code
# from flask import Flask, render_template, redirect, url_for, request, session, flash
# from flask_wtf import CSRFProtect
# from pymongo import MongoClient
# from werkzeug.security import generate_password_hash, check_password_hash
# from bson.objectid import ObjectId
# from datetime import datetime
# import os
# # for admin password
# from flask import request, session, redirect, url_for, flash, render_template
# from werkzeug.security import check_password_hash

# # Flask App Config
# app = Flask(__name__)
# app.config.from_pyfile('config.py')  # Load from config.py

# # Secret Key (with fallback)
# app.secret_key = app.config.get('SECRET_KEY', 'fallback_key')

# # Secure Session Settings
# app.config['SESSION_COOKIE_SECURE'] = True
# app.config['SESSION_COOKIE_HTTPONLY'] = True
# app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# # CSRF Protection
# csrf = CSRFProtect(app)

# # MongoDB Setup
# # MongoDB connection setup
# mongo_uri = app.config['MONGO_URI']
# client = MongoClient(mongo_uri)
# db = client["healthcare_appointments"]
# appointments_collection = db["appointments"]
# users_collection = db["users"]
# # Home Page
# @app.route('/')
# def home():
#     return render_template('index.html')

# # Patient Registration
# @app.route('/register', methods=['GET', 'POST'])
# @csrf.exempt
# def register():
#     if request.method == 'POST':
#         email = request.form['email']
#         if users_collection.find_one({'email': email}):
#             flash('User already exists!')
#             return redirect(url_for('register'))

#         hashed_pw = generate_password_hash(request.form['password'])

#         users_collection.insert_one({
#             'name': request.form['name'],
#             'email': email,
#             'password': hashed_pw,
#             'role': 'patient',
#             'phone': request.form['contact'],
#             'dob': request.form['dob'],
#             'address': request.form['address'],
#             'emergency_contact': request.form['emergency_contact'],
#             'blood_group': request.form['blood_group'],
#             'medical_history': request.form['history']
#         })

#         flash('Registration successful!')
#         return redirect(url_for('login'))

#     # Dummy user to prevent Jinja2 error
#     user = {
#         'name': '',
#         'email': '',
#         'phone': '',
#         'dob': '',
#         'address': '',
#         'emergency_contact': '',
#         'blood_group': '',
#         'medical_history': ''
#     }
#     return render_template('register.html', user=user)
# # patien update profile

# @app.route('/update_profile', methods=['GET', 'POST'])
# @csrf.exempt
# def update_profile():
#     user_id = session.get('user_id')
#     if not user_id:
#         return "Unauthorized", 401

#     if request.method == 'POST':
#         users_collection.update_one(
#             {'_id': ObjectId(user_id)},
#             {'$set': {
#                 'name': request.form['name'],
#                 'phone': request.form['phone'],
#                 'dob': request.form['dob'],
#                 'address': request.form['address'],
#                 'emergency_contact': request.form['emergency_contact'],
#                 'blood_group': request.form['blood_group'],
#                 'medical_history': request.form['medical_history']
#             }}
#         )
#         flash('Profile updated successfully!')
#         user = users_collection.find_one({'_id': ObjectId(user_id)})
#         return render_template('user_dashboard.html', user=user)

#     # GET request: Show update form
#     user = users_collection.find_one({'_id': ObjectId(user_id)})
#     return render_template('update_profile.html', user=user)



# # Doctor Registration
# @app.route('/doctor/register', methods=['GET', 'POST'])
# @csrf.exempt
# def doctor_register():
#     if request.method == 'POST':
#         email = request.form['email']
#         if users_collection.find_one({'email': email}):
#             flash('Doctor already exists!')
#             return redirect(url_for('doctor_register'))

#         hashed_pw = generate_password_hash(request.form['password'])
#         users_collection.insert_one({
#             'name': request.form['name'],
#             'email': email,
#             'password': hashed_pw,
#             'role': 'doctor',
#             'specialty': request.form['specialty'],
#             'qualification': request.form['qualification'],
#             'availability': []  # Placeholder if you expand scheduling
#         })
#         flash('Doctor registration successful!')
#         return redirect(url_for('login'))
#     return render_template('doctor_register.html')

# # Login for both patients and doctors
# @app.route('/login', methods=['GET', 'POST'])
# @csrf.exempt
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         user = users_collection.find_one({'email': email})
#         if user and check_password_hash(user['password'], request.form['password']):
#             session['user_id'] = str(user['_id'])
#             session['email'] = email
#             session['role'] = user['role']
#             flash('Login successful!')
#             return redirect(url_for('user_dashboard') if user['role'] == 'patient' else url_for('doctor_dashboard'))
#         flash('Invalid login credentials')
#     return render_template('login.html')

# # Logout
# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('Logged out successfully.')
#     return redirect(url_for('login'))

# # Patient Dashboard
# @app.route('/dashboard')
# def user_dashboard():
#     if session.get('role') != 'patient':
#         flash('Unauthorized access.')
#         return redirect(url_for('login'))

#     user = users_collection.find_one({'email': session['email']})
#     doctors = list(users_collection.find({'role': 'doctor'}))
#     appointments = list(appointments_collection.find({'patient_email': session['email']}))

#     # Add doctor names to each appointment
#     for appt in appointments:
#         doctor = users_collection.find_one({'email': appt['doctor_email']})
#         appt['doctor_name'] = doctor['name'] if doctor else 'Unknown Doctor'

#     return render_template('user_dashboard.html', user=user, doctors=doctors, appointments=appointments)


# # Doctor Dashboard
# # @app.route('/doctor/dashboard')
# # def doctor_dashboard():
# #     if session.get('role') != 'doctor':
# #         flash('Unauthorized access.')
# #         return redirect(url_for('login'))

# #     user = users_collection.find_one({'email': session['email']})
# #     appointments = list(appointments_collection.find({'doctor_email': session['email']}))
# #     return render_template('doctor_dashboard.html', user=user, appointments=appointments)

# @app.route('/doctor/dashboard')
# def doctor_dashboard():
#     if session.get('role') != 'doctor':
#         flash('Unauthorized access.')
#         return redirect(url_for('login'))

#     user = users_collection.find_one({'email': session['email']})
#     appointments = list(appointments_collection.find({'doctor_email': session['email']}))

#     # Attach patient name to each appointment
#     for appt in appointments:
#         patient = users_collection.find_one({'email': appt['patient_email']})
#         appt['patient_name'] = patient['name'] if patient else 'Unknown'
        

#     return render_template('doctor_dashboard.html', user=user, appointments=appointments)


# # Book Appointment (Patient)
# @app.route('/book_appointment/<doctor_email>', methods=['POST'])
# @csrf.exempt
# def book_appointment(doctor_email):
#     if session.get('role') != 'patient':
#         return redirect(url_for('login'))

#     appointments_collection.insert_one({
#         'patient_email': session['email'],
#         'doctor_email': doctor_email,
#         'date': request.form['date'],
#         'time': request.form['time'],
#         'reason': request.form['reason'],
#         'status': 'pending',
#         'created_at': datetime.utcnow()
#     })
#     flash('Appointment request sent!')
#     return redirect(url_for('user_dashboard'))

# # Doctor Updates Appointment (accept/reject)
# # @app.route('/update_appointment/<appointment_id>/<status>')
# # @csrf.exempt
# # def update_appointment(appointment_id, status):
# #     if session.get('role') != 'doctor':
# #         return redirect(url_for('login'))

# #     appointments_collection.update_one(
# #         {'_id': ObjectId(appointment_id)},
# #         {'$set': {'status': status}}
# #     )
# #     flash(f'Appointment {status.capitalize()}!')
# #     return redirect(url_for('doctor_dashboard'))

# # 2nd update
# @app.route('/update_appointment/<appointment_id>', methods=['POST'])
# def update_appointment(appointment_id):
#     if session.get('role') != 'doctor':
#         return redirect(url_for('login'))

#     # Validate status from form
#     status = request.form.get('status')
#     if status not in ['accepted', 'rejected']:
#         flash('Invalid status!')
#         return redirect(url_for('doctor_dashboard'))

#     try:
#         appointments_collection.update_one(
#             {'_id': ObjectId(appointment_id)},
#             {'$set': {'status': status}}
#         )
#         flash(f'Appointment {status.capitalize()}!')
#     except Exception as e:
#         flash('Error updating appointment.')

#     return redirect(url_for('doctor_dashboard'))


# # Shortcut Route
# @app.route('/doctor/login')
# def doctor_login():
#     return redirect(url_for('login'))

# # admin pannel route
# # Store these securely in production (e.g., database or env)
# registered_admins = {}  # for demo purposes only

# @app.route('/admin_register', methods=['GET', 'POST'])
# def admin_register():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']

#         if email in registered_admins:
#             flash('Admin already registered.')
#             return redirect(url_for('admin_register'))

#         # Save hashed password
#         password_hash = generate_password_hash(password)
#         registered_admins[email] = password_hash

#         flash('Admin registered successfully. Please log in.')
#         return redirect(url_for('admin_login'))

#     return render_template('admin_register.html')


# # Run App
# if __name__ == '__main__':
#     app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime
import logging
import pprint


# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config.from_pyfile('config.py')

app.secret_key = app.config.get('SECRET_KEY', 'fallback_key')

# Session security settings
app.config['SESSION_COOKIE_SECURE'] = True  # Note: Requires HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)

mongo_uri = app.config['MONGO_URI']
client = MongoClient(mongo_uri)
db = client["healthcare_appointments"]
appointments_collection = db["appointments"]
users_collection = db["users"]

# ----- Role-based access decorator -----
from functools import wraps

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login to access this page.')
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('Unauthorized access.')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# -------- WTForms definitions --------
class PatientRegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    contact = StringField('Contact Number', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()], format='%Y-%m-%d')
    address = TextAreaField('Address', validators=[DataRequired()])
    emergency_contact = StringField('Emergency Contact', validators=[DataRequired()])
    blood_group = SelectField('Blood Group', choices=[('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'), ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-')])
    history = TextAreaField('Medical History')
    submit = SubmitField('Register')

class DoctorRegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    specialty = StringField('Specialty', validators=[DataRequired()])
    qualification = StringField('Qualification', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --------------- Routes ------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = PatientRegistrationForm()
    if form.validate_on_submit():
        if users_collection.find_one({'email': form.email.data}):
            flash('User already exists!')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(form.password.data)
        users_collection.insert_one({
            'name': form.name.data,
            'email': form.email.data,
            'password': hashed_pw,
            'role': 'patient',
            'phone': form.contact.data,
            'dob': form.dob.data.strftime('%Y-%m-%d'),
            'address': form.address.data,
            'emergency_contact': form.emergency_contact.data,
            'blood_group': form.blood_group.data,
            'medical_history': form.history.data
        })
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required(role='patient')
def update_profile():
    user_id = session.get('user_id')
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Basic validation can be added here or via WTForms
        try:
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'name': request.form['name'],
                    'phone': request.form['phone'],
                    'dob': request.form['dob'],
                    'address': request.form['address'],
                    'emergency_contact': request.form['emergency_contact'],
                    'blood_group': request.form['blood_group'],
                    'medical_history': request.form['medical_history']
                }}
            )
            flash('Profile updated successfully!')
        except Exception as e:
            logging.error(f'Error updating profile: {e}')
            flash('Failed to update profile.')

        user = users_collection.find_one({'_id': ObjectId(user_id)})
        return render_template('user_dashboard.html', user=user)

    return render_template('update_profile.html', user=user)

@app.route('/doctor/register', methods=['GET', 'POST'])
def doctor_register():
    form = DoctorRegistrationForm()
    if form.validate_on_submit():
        if users_collection.find_one({'email': form.email.data}):
            flash('Doctor already exists!')
            return redirect(url_for('doctor_register'))

        hashed_pw = generate_password_hash(form.password.data)
        users_collection.insert_one({
            'name': form.name.data,
            'email': form.email.data,
            'password': hashed_pw,
            'role': 'doctor',
            'specialty': form.specialty.data,
            'qualification': form.qualification.data,
            'availability': []
        })
        flash('Doctor registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('doctor_register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({'email': form.email.data})
        if user and check_password_hash(user['password'], form.password.data):
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            session['role'] = user['role']
            flash('Login successful!')
            if user['role'] == 'patient':
                return redirect(url_for('user_dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Unknown user role.')
                return redirect(url_for('login'))
        else:
            flash('Invalid login credentials')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@login_required(role='patient')
@app.route('/dashboard')
def user_dashboard():
    user = users_collection.find_one({'email': session['email']})
    doctors = list(users_collection.find({'role': 'doctor'}))
    appointments = list(appointments_collection.find({'patient_email': session['email']}))

    for appt in appointments:
        doctor = users_collection.find_one({'email': appt['doctor_email']})
        appt['doctor_name'] = doctor['name'] if doctor else 'Unknown Doctor'

    return render_template('user_dashboard.html', user=user, doctors=doctors, appointments=appointments)

@login_required(role='doctor')
@app.route('/doctor/dashboard')
def doctor_dashboard():
    user = users_collection.find_one({'email': session['email']})
    appointments = list(appointments_collection.find({'doctor_email': session['email']}))

    for appt in appointments:
        patient = users_collection.find_one({'email': appt['patient_email']})
        appt['patient_name'] = patient['name'] if patient else 'Unknown'

    return render_template('doctor_dashboard.html', user=user, appointments=appointments)

@login_required(role='patient')
@app.route('/book_appointment/<doctor_email>', methods=['POST'])
def book_appointment(doctor_email):
    try:
        appointments_collection.insert_one({
            'patient_email': session['email'],
            'doctor_email': doctor_email,
            'date': request.form['date'],
            'time': request.form['time'],
            'reason': request.form['reason'],
            'status': 'pending',
            'created_at': datetime.utcnow()
        })
        flash('Appointment request sent!')
    except Exception as e:
        logging.error(f'Error booking appointment: {e}')
        flash('Failed to book appointment.')
    return redirect(url_for('user_dashboard'))

@login_required(role='doctor')
@app.route('/update_appointment/<appointment_id>', methods=['POST'])
def update_appointment(appointment_id):
    status = request.form.get('status')
    if status not in ['accepted', 'rejected']:
        flash('Invalid status!')
        return redirect(url_for('doctor_dashboard'))
    try:
        appointments_collection.update_one(
            {'_id': ObjectId(appointment_id)},
            {'$set': {'status': status}}
        )
        flash(f'Appointment {status.capitalize()}!')
    except Exception as e:
        logging.error(f'Error updating appointment: {e}')
        flash('Error updating appointment.')
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/login')
def doctor_login():
    return redirect(url_for('login'))

# --- Admin related ---

# Hardcoded admin credentials - replace with your own secure values
PERSONAL_ADMIN_EMAIL = "muskan@gmail.com"
PERSONAL_ADMIN_PASSWORD_HASH = "pbkdf2:sha256:260000$uDsQ2ksRVdczqZbo$51a0ba7fef0cf6cfe532eeed1df81fac62b8a53640825ebdd991d6b00cdd7aab"  # Hashed password string directly


class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        if email == PERSONAL_ADMIN_EMAIL and check_password_hash(PERSONAL_ADMIN_PASSWORD_HASH, password):
            session['user_id'] = 'admin'
            session['email'] = email
            session['role'] = 'admin'
            flash('Admin login successful!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.')
    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    users = list(users_collection.find())
    appointments = list(appointments_collection.find())
    pprint.pprint(users)
    pprint.pprint(appointments)
    return render_template('admin_dashboard.html', users=users, appointments=appointments)


@app.route('/logout')
@login_required(role='admin')
def admin_logout():
    session.clear()
    return render_template('admin_login.html', form=form)

# --- End admin related ---

if __name__ == '__main__':
    app.run(debug=True)
