from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class DatabaseService:
    def __init__(self, app=None):
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        db.init_app(app)
        with app.app_context():
            db.create_all()