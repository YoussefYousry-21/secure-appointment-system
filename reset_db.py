from app import app, db
from models import User
import pyotp

def reset_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create admin user
        admin = User(
            email="yoyoyousry@gmail.com",
            password_hash=User.hash_password("admin123"),
            phone_number="1234567890",
            email_verified=True,
            is_admin=True,
            totp_secret=pyotp.random_base32()
        )
        
        db.session.add(admin)
        db.session.commit()
        
        print(f"Database reset complete!")
        print(f"Admin user created:")
        print(f"Email: yoyoyousry@gmail.com")
        print(f"Password: admin123")

if __name__ == "__main__":
    reset_database()
