"""
This is the models.py module, responsible for defining the data models in the Flask application
using SQLAlchemy ORM and Flask-Login.

This module contains the following:

db: This is an instance of SQLAlchemy, which represents the database and provides the entry point
for any database operations.

User: This class represents the User model. It inherits from db.Model and UserMixin, the latter
providing default implementations for methods expected by Flask-Login. The User model has
attributes for 'id', 'name', 'username', 'password', 'admin', and 'blocked' status.

The User model includes a constructor that allows for the creation of new User instances.
'username', 'name', and 'password' are required parameters, whereas 'admin' and 'blocked' statuses
are optional and default to False.

The User model is essential for authentication and user management in the application.
"""

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
