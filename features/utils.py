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
