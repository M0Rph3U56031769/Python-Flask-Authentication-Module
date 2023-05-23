"""
This is the utils.py module, providing utility functions for a Flask web application
that supports user authentication and
authorization. These utility functions are mainly used for access control in the application.

This module includes:

admin_required: A decorator function for enforcing administrator-level access control.
It decorates a view function and checks if the current user is an administrator. If not,
it aborts the request with a 403 status code and adetailed error message, otherwise, it
continues to the original view function.

load_user: Function that Flask-Login uses to reload the user object from the user ID
stored in the session. It takes a user ID (in string format), converts it to an integer
and queries the User model for the user with the corresponding ID.

This module uses the Flask-Login extension for user authentication, and Flask's abort
function for aborting requests with an error code.
"""

from functools import wraps
from flask import abort
from flask_login import current_user

from app import login_manager
from features.models import User


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.admin:
            abort(403, f"You are not allowed to see this page!\n"
                       f"======================================\n"
                       f"User: {current_user.username}\n"
                       f"ID: {current_user.id}\n"
                       f"Name: {current_user.name}\n"
                       f"======================================\n"
                       f"Case is reported.\n"
                       f"Contact: danielnagy@danielnagy.hu")
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
