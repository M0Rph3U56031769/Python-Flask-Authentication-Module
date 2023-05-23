from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model, UserMixin):
    name: str = db.Column(db.String(40))
    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    admin: bool = db.Column(db.Integer, nullable=False, default=0)
    blocked: bool = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self,
                 username: str,
                 name: str,
                 password,
                 admin_property: bool = False,
                 blocked: bool = False
                 ):
        self.username = username
        self.name = name
        self.password = password
        self.admin = admin_property
        self.blocked = blocked
