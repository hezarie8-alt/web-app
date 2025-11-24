from flask_migrate import upgrade
from sqlalchemy import text

def add_created_at_column():
    """Add created_at column to user table"""
    from app import db
    try:
        # Check if column exists
        db.engine.execute(text("SELECT created_at FROM user LIMIT 1"))
        print("Column already exists")
    except:
        # Column doesn't exist, add it
        db.engine.execute(text("ALTER TABLE user ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
        db.session.commit()
        print("Column added successfully")

if __name__ == "__main__":
    add_created_at_column()