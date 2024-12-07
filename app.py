from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from flask_admin.contrib.sqla import ModelView
import os
import pyotp
import qrcode
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from extensions import db, login_manager, mail, admin
from models import User, Appointment
from forms import RegistrationForm, LoginForm, TwoFactorForm
from google_calendar import (
    create_google_auth_flow,
    get_google_calendar_service,
    create_google_calendar_event,
    update_google_calendar_event,
    delete_google_calendar_event
)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Email configuration for development (using Python's built-in SMTP debugging server)
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
mail.init_app(app)
admin.init_app(app)

login_manager.login_view = 'login'

# Admin Views
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Appointment, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_verification_email(user):
    token = os.urandom(24).hex()
    user.verification_token = token
    db.session.commit()
    
    verification_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email',
                  sender='noreply@example.com',
                  recipients=[user.email])
    msg.body = f'Please click the following link to verify your email: {verification_url}'
    mail.send(msg)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be an admin to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data,
            password_hash=User.password_hash(form.password.data),
            phone_number=form.phone_number.data,
            totp_secret=pyotp.random_base32()
        )
        db.session.add(user)
        db.session.commit()
        
        send_verification_email(user)
        flash('Registration successful. Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.email_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Your email has been verified. You can now log in.', 'success')
    else:
        flash('Invalid or expired verification token.', 'danger')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if not user.email_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            
            session['user_id'] = user.id
            return redirect(url_for('two_factor_auth'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor_auth():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    user = User.query.get(session['user_id'])
    
    if request.method == 'GET':
        # Create static/qr_codes directory if it doesn't exist
        qr_code_dir = os.path.join(app.static_folder, 'qr_codes')
        os.makedirs(qr_code_dir, exist_ok=True)
        
        # Generate QR code
        totp = pyotp.TOTP(user.totp_secret)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        provisioning_uri = totp.provisioning_uri(user.email, issuer_name="Secure Appointment System")
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Save QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        img_path = os.path.join(qr_code_dir, f'qr_{user.id}.png')
        img.save(img_path)
        
        # Pass the QR code image URL to the template
        qr_code_url = url_for('static', filename=f'qr_codes/qr_{user.id}.png')
        return render_template('2fa.html', form=form, qr_code_url=qr_code_url)
    
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.token.data):
            login_user(user, remember=True)
            session.pop('user_id', None)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA token.', 'danger')
    
    return render_template('2fa.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/appointments')
@login_required
def appointments():
    # For now, just render a simple template
    return render_template('appointments.html')

@app.route('/api/appointments', methods=['GET'])
@login_required
def get_appointments():
    try:
        print(f"Getting appointments for user {current_user.id}")
        print(f"User email: {current_user.email}")
        
        # Debug: Print all appointments in the database
        all_appointments = Appointment.query.all()
        print(f"Total appointments in database: {len(all_appointments)}")
        for apt in all_appointments:
            print(f"Appointment: {apt.id}, User: {apt.user_id}, Title: {apt.title}")
        
        # Get user's appointments
        appointments = Appointment.query.filter_by(user_id=current_user.id).all()
        print(f"Found {len(appointments)} appointments for current user")
        
        events = []
        for apt in appointments:
            event = {
                'id': apt.id,
                'title': apt.title,
                'start': apt.start_time.isoformat(),
                'end': apt.end_time.isoformat(),
                'description': apt.description,
                'allDay': False,
                'editable': True
            }
            events.append(event)
            print(f"Added event: {event}")
        
        print(f"Returning {len(events)} events")
        return jsonify(events)
    except Exception as e:
        print(f"Error getting appointments: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/appointments', methods=['POST'])
@login_required
def create_appointment():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['title', 'start_time', 'end_time']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Parse the datetime strings
        try:
            start_time = datetime.fromisoformat(data['start_time'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00'))
        except ValueError as e:
            return jsonify({'error': f'Invalid datetime format: {str(e)}'}), 400

        # Create the appointment
        appointment = Appointment(
            user_id=current_user.id,
            title=data['title'],
            start_time=start_time,
            end_time=end_time,
            description=data.get('description', '')
        )
        
        db.session.add(appointment)
        
        # Sync with Google Calendar if credentials exist
        if current_user.google_calendar_credentials:
            service = get_google_calendar_service(current_user.google_calendar_credentials)
            if service:
                event_id = create_google_calendar_event(service, appointment)
                appointment.google_calendar_event_id = event_id
        
        db.session.commit()
        
        # Return the created appointment data
        return jsonify({
            'message': 'Appointment created successfully',
            'appointment': {
                'id': appointment.id,
                'title': appointment.title,
                'start': appointment.start_time.isoformat(),
                'end': appointment.end_time.isoformat(),
                'description': appointment.description
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/google-auth')
@login_required
def google_auth():
    flow = create_google_auth_flow()
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/google-auth-callback')
@login_required
def google_auth_callback():
    flow = create_google_auth_flow()
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    current_user.google_calendar_credentials = credentials.to_json()
    db.session.commit()
    flash('Google Calendar connected successfully!', 'success')
    return redirect(url_for('appointments'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    appointments = Appointment.query.all()
    return render_template('admin/dashboard.html', users=users, appointments=appointments)

@app.route('/resend-verification/<email>')
def resend_verification(email):
    user = User.query.filter_by(email=email).first()
    if user:
        if not user.is_verified:
            send_verification_email(user)
            flash('Verification email has been resent. Please check your inbox.', 'success')
        else:
            flash('Email is already verified.', 'info')
    else:
        flash('Email not found.', 'danger')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/debug/appointments')
@login_required
def debug_appointments():
    appointments = Appointment.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': apt.id,
        'title': apt.title,
        'start': apt.start_time.isoformat(),
        'end': apt.end_time.isoformat(),
        'description': apt.description,
        'user_id': apt.user_id
    } for apt in appointments])

# Admin routes
@app.route('/admin/users/<int:user_id>/appointments')
@login_required
@admin_required
def user_appointments(user_id):
    user = User.query.get_or_404(user_id)
    appointments = Appointment.query.filter_by(user_id=user_id).all()
    return render_template('admin/user_appointments.html', user=user, appointments=appointments)

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': 'Cannot reset admin password'}), 403
    
    # Generate a random password
    new_password = os.urandom(8).hex()
    user.password_hash = User.hash_password(new_password)
    db.session.commit()
    
    # Send email with new password
    msg = Message('Password Reset',
                 sender=app.config['MAIL_DEFAULT_SENDER'],
                 recipients=[user.email])
    msg.body = f'Your password has been reset by an administrator. Your new password is: {new_password}'
    mail.send(msg)
    
    return jsonify({'message': 'Password reset successful. User has been notified via email.'})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': 'Cannot delete admin user'}), 403
    
    # Delete all user's appointments
    Appointment.query.filter_by(user_id=user_id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/appointments/<int:appointment_id>', methods=['GET'])
@login_required
def get_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if not current_user.is_admin and appointment.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    return jsonify({
        'id': appointment.id,
        'title': appointment.title,
        'start': appointment.start_time.isoformat(),
        'end': appointment.end_time.isoformat(),
        'description': appointment.description
    })

@app.route('/api/appointments/<int:appointment_id>', methods=['PUT'])
@login_required
def update_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if not current_user.is_admin and appointment.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        start_time = datetime.fromisoformat(data['start_time'].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00'))
    except ValueError as e:
        return jsonify({'error': f'Invalid datetime format: {str(e)}'}), 400
    
    appointment.title = data['title']
    appointment.start_time = start_time
    appointment.end_time = end_time
    appointment.description = data.get('description', '')
    
    # Update Google Calendar if integrated
    if appointment.google_calendar_event_id and appointment.user.google_calendar_credentials:
        service = get_google_calendar_service(appointment.user.google_calendar_credentials)
        if service:
            update_google_calendar_event(service, appointment)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Appointment updated successfully',
        'appointment': {
            'id': appointment.id,
            'title': appointment.title,
            'start': appointment.start_time.isoformat(),
            'end': appointment.end_time.isoformat(),
            'description': appointment.description
        }
    })

@app.route('/api/appointments/<int:appointment_id>', methods=['DELETE'])
@login_required
def delete_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if not current_user.is_admin and appointment.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete from Google Calendar if integrated
    if appointment.google_calendar_event_id and appointment.user.google_calendar_credentials:
        service = get_google_calendar_service(appointment.user.google_calendar_credentials)
        if service:
            delete_google_calendar_event(service, appointment.google_calendar_event_id)
    
    db.session.delete(appointment)
    db.session.commit()
    
    return jsonify({'message': 'Appointment deleted successfully'})

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
