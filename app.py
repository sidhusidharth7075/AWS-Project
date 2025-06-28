# Extended Flask App for MedTrack
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import uuid
from functools import wraps
from dotenv import load_dotenv
from boto3.dynamodb.conditions import Attr
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ---------- In-Memory Storage ----------
users = {}                 # userid: {...}
appointments_dict = {}     # appointment_id: {...}
diagnoses = []             # list of diagnosis dicts
notifications = []         # list of notification dicts

# Load configuration from environment
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'UsersTable')
APPOINTMENTS_TABLE_NAME = os.environ.get('APPOINTMENTS_TABLE_NAME', 'AppointmentsTable')
NOTIFICATIONS_TABLE_NAME = os.environ.get('NOTIFICATIONS_TABLE_NAME', 'NotificationsTable')
DIAGNOSES_TABLE_NAME = os.environ.get('DIAGNOSES_TABLE_NAME', 'DiagnosesTable')

try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
    user_table = dynamodb.Table(USERS_TABLE_NAME)
    appointment_table = dynamodb.Table(APPOINTMENTS_TABLE_NAME)
    notification_table = dynamodb.Table(NOTIFICATIONS_TABLE_NAME)
    diagnosis_table = dynamodb.Table(DIAGNOSES_TABLE_NAME)
    DYNAMO_ENABLED = True
except (NoCredentialsError, PartialCredentialsError, Exception) as e:
    DYNAMO_ENABLED = False
    user_table = None
    appointment_table = None
    notification_table = None
    diagnosis_table = None
    print("\u26a0\ufe0f DynamoDB not connected — fallback to SQLite or memory")


# ---------- DynamoDB Storage Helpers ----------
def save_user_dynamodb(user_id, user_data):
    user_table.put_item(Item={
        'user_id': user_id,
        'name': user_data['name'],
        'email': user_data['email'],
        'password': user_data['password'],
        'role': user_data['role'],
        'age': user_data['extra'].get('age'),
        'gender': user_data['extra'].get('gender'),
        'address': user_data['extra'].get('address'),
        'specialization': user_data['extra'].get('specialization'),
        'experience': user_data['extra'].get('experience'),
        'medical_history': user_data['extra'].get('medical_history')
    })


def get_user_by_email_dynamodb(email):
    response = user_table.scan(
        FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(email)
    )
    items = response.get('Items', [])
    if items:
        user = items[0]
        return user['user_id'], {
            'name': user['name'],
            'email': user['email'],
            'password': user['password'],
            'role': user['role'],
            'extra': {
                'age': user.get('age'),
                'gender': user.get('gender'),
                'address': user.get('address'),
                'specialization': user.get('specialization'),
                'experience': user.get('experience'),
                'medical_history': user.get('medical_history')
            }
        }
    return None, None


# ---------- Logging Setup ----------
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


# ---------- Helper Functions ----------
def is_logged_in():
    return 'email' in session

def get_user_role(email):
    try:
        response = user_table.get_item(Key={'email': email})
        return response.get('Item', {}).get('role', None)
    except Exception as e:
        logger.error(f"Error fetching role: {e}")
        return None

# ---------- Helper Functions ----------
def is_logged_in():
    return 'email' in session

def get_user_role(email):
    try:
        response = user_table.get_item(Key={'email': email})
        return response.get('Item', {}).get('role', None)
    except Exception as e:
        logger.error(f"Error fetching role: {e}")
        return None

def send_email(to_email, subject, message):
    if not ENABLE_EMAIL:
        logger.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'html'))

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Email failed to send: {e}")

def publish_to_sns(message, subject="MedTrack Notification"):
    if not ENABLE_SNS:
        logger.info("[SNS Skipped] Message: {}".format(message))
        return

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS published: {response['MessageId']}")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")

# ---------- Utility: Role Required Decorator ----------

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'userid' not in session or session.get('role') != role:
                flash("Unauthorized access.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------- Storage Abstraction ----------

def save_user(user_id, user_data):
    if DYNAMO_ENABLED and user_table:
        save_user_dynamodb(user_id, user_data)
    else:
        users[user_id] = user_data

def get_user_by_email(email):
    if DYNAMO_ENABLED and user_table:
        return get_user_by_email_dynamodb(email)
    else:
        for uid, user in users.items():
            if user['email'] == email:
                return uid, user
        return None, None


# ---------- Routes ----------
# Home Page
@app.route('/')
def index():
    if is_logged_in():
        role = get_user_role(session['email'])
        if role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif role == 'patient':
            return redirect(url_for('patient_dashboard'))
        # You can add more role redirects here if needed
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():  # Redirect logged-in users
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Validate required fields
        required_fields = ['name', 'email', 'password', 'age', 'gender', 'role']
        for field in required_fields:
            if field not in request.form or not request.form[field].strip():
                flash(f'Please fill in the {field} field.', 'danger')
                return render_template('register.html')

        if request.form['password'] != request.form.get('confirm_password', ''):
            flash("Passwords do not match.", 'danger')
            return render_template('register.html')

        email = request.form['email']
        # Check if email already exists
        if DYNAMO_ENABLED:
            existing_user = user_table.get_item(Key={'email': email}).get('Item')
            if existing_user:
                flash('Email already registered.', 'danger')
                return render_template('register.html')
        else:
            if any(user['email'] == email for user in users.values()):
                flash('Email already registered.', 'danger')
                return render_template('register.html')

        # Generate user ID
        generated_id = f"{request.form['role'][:3].upper()}{str(uuid.uuid4())[:5]}"

        user_data = {
            'name': request.form['name'],
            'email': email,
            'password': generate_password_hash(request.form['password']),
            'role': request.form['role'],
            'extra': {
                'age': request.form.get('age'),
                'gender': request.form.get('gender'),
                'address': request.form.get('address'),
                'specialization': request.form.get('specialization'),
                'experience': request.form.get('experience'),
                'medical_history': request.form.get('medical_history')
            }
        }

        # Save to DynamoDB or memory
        if DYNAMO_ENABLED:
            save_user_dynamodb(generated_id, user_data)
        else:
            users[generated_id] = user_data

        # Optional: Send welcome email
        if ENABLE_EMAIL:
            welcome_msg = f"""
                <h2>Welcome to MedTrack, {user_data['name']}!</h2>
                <p>Your registration was successful.</p>
                <p>User ID: <strong>{generated_id}</strong></p>
            """
            send_email(user_data['email'], "Welcome to MedTrack", welcome_msg)

        # Optional: SNS notification
        if ENABLE_SNS and sns:
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Message=f"New user registered: {user_data['name']} ({user_data['email']}) as {user_data['role']}",
                    Subject="New Registration - MedTrack"
                )
            except Exception as e:
                logger.error(f"SNS publish failed: {e}")

        logging.info(f"User registered: {generated_id}")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# Login validation
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():  # If already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        selected_role = request.form['role']

        if not email or not password or not selected_role:
            flash("All fields are required.", 'danger')
            return render_template('login.html')

        user_id, user = get_user_by_email(email)

        if user_id and check_password_hash(user['password'], password):
            actual_role = user['role']
            if actual_role != selected_role:
                flash("Role mismatch! Please select the correct role for your account.", 'danger')
                logging.warning(f"Role mismatch for email: {email} (selected: {selected_role}, actual: {actual_role})")
                return redirect(url_for('login'))

            # Set session
            session['userid'] = user_id
            session['role'] = actual_role
            session['email'] = user['email']
            session['name'] = user.get('name', '')

            # Update login count (optional)
            try:
                user_table.update_item(
                    Key={'email': email},
                    UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc',
                    ExpressionAttributeValues={':inc': 1, ':zero': 0}
                )
            except Exception as e:
                logger.error(f"Failed to update login count: {e}")

            flash("Login successful.", "success")
            return redirect(url_for(f"{actual_role}_dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            logging.warning(f"Login failed for email: {email}")

    return render_template('login.html')

# Logout User
@app.route('/logout')
def logout():
    session.pop('userid', None)
    session.pop('role', None)
    session.pop('email', None)
    session.pop('name', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ---------- Patient Dashboard ----------
@app.route('/patient_dashboard')
@role_required('patient')
def patient_dashboard():
    user_id = session['userid']
    user = users[user_id]
    email = user['email']

    # Get search query
    search_query = request.args.get('search', '').strip().lower()

    # Fetch appointments from DynamoDB
    try:
        response = appointment_table.query(
            IndexName='PatientEmailIndex',
            KeyConditionExpression="patient_email = :email",
            ExpressionAttributeValues={":email": email}
        )
        appointments = response.get('Items', [])
    except Exception as e:
        logger.error(f"Failed to fetch appointments for patient: {e}")
        appointments = []

    # Apply search filter
    if search_query:
        filtered_appointments = []
        for a in appointments:
            doctor_id = a.get('doctor_id')
            doctor_name = users.get(doctor_id, {}).get('name', '').lower()
            status = a.get('status', '').lower()
            if search_query in doctor_name or search_query in status:
                filtered_appointments.append(a)
        appointments = filtered_appointments

    # Stats
    pending = sum(1 for a in appointments if a.get('status') == 'Pending')
    completed = sum(1 for a in appointments if a.get('status') == 'Completed')
    total = len(appointments)

    # Available doctors
    doctor_list = {uid: info for uid, info in users.items() if info['role'] == 'doctor'}

    return render_template(
        'patient_dashboard.html',
        user=user,
        appointments=appointments,
        pending=pending,
        completed=completed,
        total=total,
        doctor_list=doctor_list,
        users=users
    )


# ---------- Doctor Dashboard ----------
@app.route('/doctor_dashboard')
@role_required('doctor')
def doctor_dashboard():
    user_id = session['userid']
    user = users[user_id]
    email = user['email']

    # Get search query
    search_query = request.args.get('search', '').strip().lower()

    # Fetch appointments from DynamoDB
    try:
        response = appointment_table.query(
            IndexName='DoctorEmailIndex',
            KeyConditionExpression="doctor_email = :email",
            ExpressionAttributeValues={":email": email}
        )
        appointments = response.get('Items', [])
    except Exception as e:
        logger.error(f"Failed to fetch appointments for doctor: {e}")
        appointments = []

    # Apply search filter
    if search_query:
        appointments = [
            a for a in appointments
            if search_query in users.get(a.get('patient_id'), {}).get('name', '').lower()
        ]

    # Stats
    pending = sum(1 for a in appointments if a.get('status') == 'Pending')
    completed = sum(1 for a in appointments if a.get('status') == 'Completed')
    total = len(appointments)

    return render_template(
        'doctor_dashboard.html',
        user=user,
        appointments=appointments,
        pending=pending,
        completed=completed,
        total=total,
        users=users
    )

# ---------- Book Appointment ----------
@app.route('/book_appointment', methods=['GET', 'POST'])
@role_required('patient')
def book_appointment():
    if request.method == 'POST':
        appointment_id = str(uuid.uuid4())[:8]
        patient_id = session['userid']
        doctor_id = request.form['doctor_id']
        appointment_date = request.form['appointment_date']
        appointment_time = request.form['appointment_time']
        symptoms = request.form['symptoms']
        status = 'Pending'
        created_at = datetime.now().isoformat()

        # Get patient and doctor info for notifications
        patient = users.get(patient_id, {})
        doctor = users.get(doctor_id, {})
        patient_name = patient.get('name', 'Patient')
        patient_email = patient.get('email')
        doctor_name = doctor.get('name', 'Doctor')
        doctor_email = doctor.get('email')

        appointment_item = {
            'appointment_id': appointment_id,
            'patient_id': patient_id,
            'doctor_id': doctor_id,
            'date': appointment_date,
            'time': appointment_time,
            'symptoms': symptoms,
            'status': status,
            'created_at': created_at,
            'patient_name': patient_name,
            'doctor_name': doctor_name,
            'patient_email': patient_email,
            'doctor_email': doctor_email
        }

        try:
            appointment_table.put_item(Item=appointment_item)

            # Save notification for doctor
            notification_table.put_item(Item={
                'id': str(uuid.uuid4()),
                'user_id': doctor_id,
                'message': f"New appointment booked by {patient_name}",
                'timestamp': created_at
            })

            # Send confirmation email to patient
            send_email(
                patient_email,
                "Appointment Confirmation",
                f"<h3>Appointment Booked</h3><p>Date: {appointment_date}<br>Time: {appointment_time}</p>"
            )

            # Send email to doctor
            send_email(
                doctor_email,
                "New Appointment Alert",
                f"<h3>New Appointment</h3><p>Patient: {patient_name}<br>Date: {appointment_date}<br>Time: {appointment_time}<br>Symptoms: {symptoms}</p>"
            )

            logging.info(f"Appointment booked: {appointment_item}")
            flash("Appointment booked successfully.", "success")
            return redirect(url_for('patient_dashboard'))

        except Exception as e:
            logger.error(f"Failed to book appointment: {e}")
            flash("An error occurred while booking the appointment.", "danger")
            return redirect(url_for('book_appointment'))

    doctors = {uid: info for uid, info in users.items() if info['role'] == 'doctor'}
    return render_template('book_appointment.html', doctors=doctors)


# ---------- View Appointment ----------
@app.route('/appointment/<appointment_id>', methods=['GET', 'POST'])
@role_required('doctor')
def view_appointment_doctor(appointment_id):
    try:
        # Fetch appointment from DynamoDB
        response = appointment_table.get_item(Key={'appointment_id': appointment_id})
        appointment = response.get('Item')

        if not appointment or appointment['doctor_id'] != session['userid']:
            flash("Unauthorized or invalid appointment.", "danger")
            return redirect(url_for('doctor_dashboard'))

        # If doctor submits diagnosis
        if request.method == 'POST':
            diagnosis = request.form['diagnosis']
            treatment_plan = request.form['treatment_plan']
            prescription = request.form['prescription']
            updated_at = datetime.now().isoformat()

            # Update appointment in DynamoDB
            appointment_table.update_item(
                Key={'appointment_id': appointment_id},
                UpdateExpression="SET diagnosis=:d, treatment_plan=:t, prescription=:p, #s=:s, updated_at=:u",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={
                    ':d': diagnosis,
                    ':t': treatment_plan,
                    ':p': prescription,
                    ':s': 'Completed',
                    ':u': updated_at
                }
            )

            # Send email to patient if enabled
            if ENABLE_EMAIL:
                patient = users.get(appointment['patient_id'], {})
                patient_email = patient.get('email')
                doctor = users.get(session['userid'], {})
                doctor_name = doctor.get('name', 'Doctor')

                if patient_email:
                    email_body = (
                        f"<h3>Appointment Completed</h3>"
                        f"<p>Diagnosis: {diagnosis}</p>"
                        f"<p>Treatment Plan: {treatment_plan}</p>"
                        f"<p>Prescribed: {prescription}</p>"
                    )
                    send_email(patient_email, "Your Diagnosis Report", email_body)

            flash("Diagnosis submitted successfully.", "success")
            return redirect(url_for('doctor_dashboard'))

        # Render doctor appointment view
        patient = users.get(appointment['patient_id'], {})
        return render_template(
            'view_appointment_doctor.html',
            appointment=appointment,
            patient=patient
        )

    except Exception as e:
        logger.error(f"Failed to load appointment: {e}")
        flash("Error loading appointment.", "danger")
        return redirect(url_for('doctor_dashboard'))


@app.route('/submit_diagnosis/<appointment_id>', methods=['POST'])
@role_required('doctor')
def submit_diagnosis(appointment_id):
    appointment = appointments_dict.get(appointment_id)
    
    if not appointment or appointment['doctor_id'] != session['userid']:
        flash("Unauthorized or invalid appointment.", "danger")
        return redirect(url_for('doctor_dashboard'))  # Must be valid for logged-in doctor

    # Update the appointment with diagnosis data
    appointment['diagnosis'] = request.form['diagnosis']
    appointment['treatment_plan'] = request.form['treatment_plan']
    appointment['prescription'] = request.form['prescription']
    appointment['status'] = 'Completed'

    flash("Diagnosis submitted successfully!", "success")
    return redirect(url_for('doctor_dashboard'))


@app.route('/appointment_patient/<appointment_id>')
@role_required('patient')
def view_appointment_patient(appointment_id):
    appointment = appointments_dict.get(appointment_id)
    if not appointment or appointment['patient_id'] != session['userid']:
        flash("Unauthorized or invalid appointment.", "danger")
        return redirect(url_for('patient_dashboard'))

    if 'created_at' not in appointment:
        appointment['created_at'] = datetime.now()

    doctor = users.get(appointment['doctor_id'], {})
    return render_template('view_appointment_patient.html', appointment=appointment, doctor=doctor)

# ---------- Doctor Profile ----------
@app.route('/doctor/profile', methods=['GET', 'POST'])
@role_required('doctor')
def doctor_profile():
    user_id = session['userid']
    try:
        response = user_table.get_item(Key={'user_id': user_id})
        user = response.get('Item', {})

        if request.method == 'POST':
            name = request.form.get('name')
            age = request.form.get('age')
            gender = request.form.get('gender')
            specialization = request.form.get('specialization')

            update_expression = "SET #name = :name, age = :age, gender = :gender, specialization = :spec"
            expression_values = {
                ':name': name,
                ':age': age,
                ':gender': gender,
                ':spec': specialization
            }

            user_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ExpressionAttributeNames={'#name': 'name'}
            )

            session['name'] = name
            flash("Profile updated successfully.", "success")
            return redirect(url_for('doctor_profile'))

        return render_template('doctor_profile.html', user=user)
    except Exception as e:
        logger.error(f"Doctor profile error: {e}")
        flash("Failed to load doctor profile.", "danger")
        return redirect(url_for('doctor_dashboard'))


# ---------- Patient Profile ----------
@app.route('/patient/profile', methods=['GET', 'POST'])
@role_required('patient')
def patient_profile():
    user_id = session['userid']
    try:
        response = user_table.get_item(Key={'user_id': user_id})
        user = response.get('Item', {})

        if request.method == 'POST':
            name = request.form.get('name')
            age = request.form.get('age')
            gender = request.form.get('gender')

            update_expression = "SET #name = :name, age = :age, gender = :gender"
            expression_values = {
                ':name': name,
                ':age': age,
                ':gender': gender
            }

            user_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ExpressionAttributeNames={'#name': 'name'}
            )

            session['name'] = name
            flash("Profile updated successfully.", "success")
            return redirect(url_for('patient_profile'))

        return render_template('patient_profile.html', user=user)
    except Exception as e:
        logger.error(f"Patient profile error: {e}")
        flash("Failed to load patient profile.", "danger")
        return redirect(url_for('patient_dashboard'))


@app.route('/view_diagnosis')
@role_required('patient')
def view_diagnosis():
    patient_email = session['email']
    diagnoses = []

    try:
        # Use GSI if available; else fallback to scan
        response = appointment_table.scan(
            FilterExpression="#patient_email = :email AND attribute_exists(diagnosis)",
            ExpressionAttributeNames={
                "#patient_email": "patient_email"
            },
            ExpressionAttributeValues={
                ":email": patient_email
            }
        )
        diagnoses = response.get('Items', [])
    except Exception as e:
        logger.error(f"Failed to fetch diagnosis records: {e}")
        flash("Could not retrieve diagnosis information.", "danger")

    return render_template('view_diagnosis.html', diagnoses=diagnoses)


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200


# ---------- Error Handlers ----------
@app.errorhandler(404)
def page_not_found(error):
    logging.warning(f"404 Not Found: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"500 Internal Server Error: {error}")
    return render_template('500.html'), 500


# ---------- Notifications ----------
@app.route('/notifications')
def view_notifications():
    if not is_logged_in():
        flash('Please log in to view notifications.', 'danger')
        return redirect(url_for('login'))

    try:
        email = session['email']

        response = notification_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('user_email').eq(email)
        )
        user_notifications = response.get('Items', [])

        return render_template('notifications.html', notifications=user_notifications)

    except Exception as e:
        logger.error(f"Failed to fetch notifications: {e}")
        flash("Could not load notifications.", "danger")
        return redirect(url_for('dashboard'))

# ---------- Run ----------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)



