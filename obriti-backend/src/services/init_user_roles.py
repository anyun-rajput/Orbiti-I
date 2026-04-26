"""
Initialize user roles and migrate existing users
"""
from sqlalchemy.orm import Session
from models.scan import Role, User, Base
from services.db import get_db, engine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_roles():
    """Initialize default roles in the database"""
    try:
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        
        db = next(get_db())
        
        # Check if roles already exist
        existing_roles = db.query(Role).count()
        if existing_roles > 0:
            logger.info("Roles already initialized")
            return
        
        # Create default roles
        admin_role = Role(
            name="admin",
            description="Full access to all features and user management"
        )
        
        org_team_role = Role(
            name="org_team", 
            description="Limited access to dashboard and vulnerability analysis"
        )
        
        db.add(admin_role)
        db.add(org_team_role)
        db.commit()
        
        logger.info("Successfully created default roles")
        
        # Update existing users to have org_team role by default
        users_without_role = db.query(User).filter(User.role_id == None).all()
        for user in users_without_role:
            user.role_id = 2  # org_team role
        
        db.commit()
        logger.info(f"Updated {len(users_without_role)} existing users with org_team role")
        
    except Exception as e:
        logger.error(f"Error initializing roles: {e}")
        if 'db' in locals():
            db.rollback()
    finally:
        if 'db' in locals():
            db.close()

def create_admin_user(username: str, password: str, email: str, first_name: str = None, last_name: str = None):
    """Create an admin user"""
    try:
        from api.scan import get_password_hash
        
        db = next(get_db())
        
        # Check if admin user already exists
        existing_admin = db.query(User).join(Role).filter(Role.name == "admin").first()
        if existing_admin:
            logger.info("Admin user already exists")
            return existing_admin
        
        # Get admin role
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if not admin_role:
            logger.error("Admin role not found. Please run init_roles() first")
            return None
        
        # Create admin user
        hashed_password = get_password_hash(password)
        admin_user = User(
            username=username,
            hashed_password=hashed_password,
            email=email,
            first_name=first_name,
            last_name=last_name,
            role_id=admin_role.id,
            is_active=True
        )
        
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        
        logger.info(f"Successfully created admin user: {username}")
        return admin_user
        
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        if 'db' in locals():
            db.rollback()
        return None
    finally:
        if 'db' in locals():
            db.close()

if __name__ == "__main__":
    # Initialize roles
    init_roles()
    
    # Create default admin user - requires ADMIN_PASSWORD environment variable
    admin_password = os.getenv("ADMIN_PASSWORD")
    if not admin_password:
        raise ValueError(
            "ADMIN_PASSWORD environment variable must be set to create admin user. "
            "Set it in your .env file or system environment before running this script."
        )
    
    create_admin_user(
        username=os.getenv("ADMIN_USERNAME", "admin"),
        password=admin_password,
        email=os.getenv("ADMIN_EMAIL", "admin@orbit-i.com"),
        first_name="System",
        last_name="Administrator"
    )
