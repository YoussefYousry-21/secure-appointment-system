# Secure Appointment Booking System

A Flask-based web application for secure appointment booking with advanced authentication and management features.

## Features

- User Authentication with 2FA support
- Appointment Management
- Admin Dashboard
- Calendar Integration
- Email Notifications
- Google Calendar Synchronization (optional)

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- SQLite3
- SMTP server for email notifications (development SMTP server included)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure_appointment_system
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Unix/MacOS:
```bash
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Create a `.env` file in the root directory with the following content:
```
SECRET_KEY=your_secret_key_here
MAIL_SERVER=localhost
MAIL_PORT=2525
MAIL_USE_TLS=False
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=noreply@example.com
```

## Running the Application

1. Start the debug SMTP server (in a separate terminal):
```bash
python debug_smtp.py
```

2. Run the Flask application:
```bash
python app.py
```

3. Access the application at `http://localhost:5000`

## Default Admin Account

The system creates a default admin account on first run:
- Email: admin@example.com
- Password: admin123

Change these credentials immediately after first login.

## Usage

### User Features
- Register/Login with email verification
- Enable/Disable 2FA
- Create, view, and manage appointments
- View calendar of appointments
- Receive email notifications

### Admin Features
- Manage users (view, reset password, delete)
- View and manage all appointments
- Access system statistics
- Monitor user activity

## Development

The project structure is organized as follows:
```
secure_appointment_system/
├── app.py              # Main application file
├── models.py           # Database models
├── forms.py            # Form definitions
├── extensions.py       # Flask extensions
├── debug_smtp.py       # Development SMTP server
├── requirements.txt    # Project dependencies
├── .env               # Environment variables
└── templates/         # HTML templates
    ├── base.html
    ├── profile.html
    ├── appointments.html
    └── admin/
        └── dashboard.html
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security Considerations

- All passwords are hashed using bcrypt
- Session management with Flask-Login
- Role-based access control
- Input validation and sanitization
- CSRF protection
- Rate limiting on sensitive endpoints

## License

[MIT License](LICENSE)

## Support

For support, please open an issue in the repository.
