from flask_login import UserMixin

from app import db
from app import login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.image_file}')"


class Agents(db.Model):
    guid = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String, unique=True, nullable=False)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    hostname = db.Column(db.String(60), nullable=False)
    os = db.Column(db.String(20), nullable=False)
    running = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.guid}','{self.ip}','{self.username}','{self.password}','{self.port}','{self.hostname}','{self.os}','{self.running}')"
