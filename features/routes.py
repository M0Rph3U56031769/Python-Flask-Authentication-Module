# routes.py
"""
This is the routes.py module, defining the routes (URLs) for a Flask web application that supports user authentication,
authorization and user profile management.

This module includes:

load_user: Function that Flask-Login uses to reload the user object from the user ID stored in the session.
It takes a user ID and returns the corresponding User object.

define_routes: Function that defines the routes for the Flask application. It includes the following routes:

/update_my_profile: Endpoint for authenticated users to update their profiles.

/new_user: Endpoint for administrators to create new users.

/: Home page of the website.

/delete_user: Endpoint for administrators to delete users. Expects a user_id in the POST request body.

/update_user: Endpoint for updating a user's details. Expects a user_id and the new details in the POST request.

/admin: Administrative page showing all users. Accessible only to administrators.

/login: Login page.

/dashboard: Personal dashboard for authenticated users.

/logout: Endpoint to log out the current user.

/register: Registration page for new users.

This module uses Flask's routing mechanism to map URLs to Python function calls, providing the HTTP interface for the application.
"""

from flask import render_template, url_for, redirect, request, jsonify
from flask_login import login_required, logout_user, current_user
from flask_login import login_user
from app import login_manager  # Import login_manager

from .forms import NewUserForm, UpdateUserForm, LoginForm, RegisterForm
from .models import db, User
from .utils import admin_required


# Set user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# define routes here
def define_routes(app, bcrypt):
    @app.route('/update_my_profile', methods=['GET', 'POST'])
    @login_required
    def update_my_profile():
        form = UpdateUserForm()

        # Load current data
        if request.method == 'GET':
            form.name.data = current_user.name
            form.username.data = current_user.username

        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify(result='error', message='This username is already taken. Please choose another.')
            else:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                current_user.name = form.name.data
                current_user.username = form.username.data
                current_user.password = hashed_password
                db.session.commit()
                return jsonify(result='success')  # Return success status as JSON

        return render_template('update_my_profile.html', form=form, user=current_user)

    @app.route('/new_user', methods=['GET', 'POST'])
    @admin_required
    @login_required
    def new_user():
        print("NEW USER:")
        form = NewUserForm()
        print(form.validate_on_submit())
        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if not existing_user:
                hashed_password = bcrypt.generate_password_hash(form.password.data)
                new_user_instance = User(
                    name=(form.name.data or "John/Jane Doe") if form.name.data.strip() != "" else "John/Jane Doe",
                    username=form.username.data,
                    password=hashed_password,
                    admin_property=form.admin.data,
                    blocked=form.blocked.data)
                print(f"form username: {form.username.data}")
                db.session.add(new_user_instance)
                db.session.commit()
                return redirect(url_for('admin'))
        else:
            print(form.errors)
        return render_template('new_user.html', form=form)

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/delete_user', methods=['POST'])
    @login_required
    @admin_required
    def delete_user():
        data = request.get_json()
        user_id = data.get('user_id')
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"result": "success"})
        else:
            return jsonify({"result": "error", "message": "User not found"})

    @app.route('/update_user', methods=['POST'])
    @login_required
    def update_user():
        user_id = request.form.get('user_id')
        new_name: str = request.form.get('new_name')
        new_username: str = request.form.get('new_username')
        blocked: int = int(request.form.get('blocked'))
        admin_property: int = int(request.form.get('admin'))

        # email = str(request.form.get('email'))

        user = User.query.get(user_id)
        if user:
            user.name = new_name
            user.username = new_username
            user.blocked = blocked
            # user.email = email
            user.admin = admin_property
            db.session.commit()
            return jsonify({"result": "success"})
        else:
            return jsonify({"result": "error", "message": "User not found"})

    @app.route('/admin', methods=['GET', 'POST'])
    @admin_required
    @login_required
    def admin():
        all_users = User.query.all()
        return render_template('admin.html', user=current_user, all_users=all_users)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            blocked: bool = bool(user.blocked)
            if user and not blocked:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
        return render_template('login.html', form=form)

    @app.route('/dashboard', methods=['GET', 'POST'])
    @login_required
    def dashboard():
        return render_template('dashboard.html', user=current_user)

    @app.route('/logout', methods=['GET', 'POST'])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()

        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user_instance = User(username=form.username.data,
                                     name=form.name.data,
                                     password=hashed_password)
            db.session.add(new_user_instance)
            db.session.commit()
            return redirect(url_for('login'))

        return render_template('register.html', form=form)
