# routes.py
"""
This is the routes.py module, defining the routes (URLs) for a Flask web application
that supports user authentication, authorization and user profile management.

This module includes:

load_user: Function that Flask-Login uses to reload the user object from the user
ID stored in the session. It takes a user ID and returns the corresponding User object.

define_routes: Function that defines the routes for the Flask application. It includes
the following routes:

/update_my_profile: Endpoint for authenticated users to update their profiles.

/new_user: Endpoint for administrators to create new users.

/: Home page of the website.

/delete_user: Endpoint for administrators to delete users. Expects a user_id in
the POST request body.

/update_user: Endpoint for updating a user's details. Expects a user_id and the new
details in the POST request.

/admin: Administrative page showing all users. Accessible only to administrators.

/login: Login page.

/dashboard: Personal dashboard for authenticated users.

/logout: Endpoint to log out the current user.

/register: Registration page for new users.

This module uses Flask's routing mechanism to map URLs to Python function calls,
providing the HTTP interface for the application.
"""

from flask import render_template, url_for, redirect, request, jsonify
from flask_login import login_required, logout_user, current_user
from flask_login import login_user
from app import login_manager

from .forms import NewUserForm, UpdateUserForm, LoginForm, RegisterForm
from .models import db, User
from .utils import admin_required


# Set user loader function
@login_manager.user_loader
def load_user(user_id):
    """
    Fetches a User instance that matches the provided user_id.

    This function is decorated with the `user_loader` function from Flask's login_manager.
    It's used to reload the user object from the user ID stored in the session. It takes
    a unicode user_id and converts it into an int, then uses it to get the User instance
    from the database.

    Args:
        user_id (str): A unicode string representing the user's unique identifier.

    Returns:
        User: A User instance that matches the provided user_id. If no match, returns None.
    """
    return User.query.get(int(user_id))


# define routes here
def define_routes(app, bcrypt):
    """
    Defines all routes for the Flask application.

    This function takes in two parameters: a Flask application instance, and a bcrypt object for
    password hashing.

    The routes defined include: '/update_my_profile', '/new_user', '/', '/delete_user',
    '/update_user', '/admin', '/login', '/dashboard', '/logout', and '/register'. Each of these
    routes is associated with a specific function that handles the logic for that route.

    Each route function may be decorated with one or more decorators that enforce certain
    conditions, such as requiring the user to be logged in or requiring the user to be an admin.

    Args:
        app (Flask): The Flask application instance.
        bcrypt (Bcrypt): The bcrypt object used for password hashing.

    Returns:
        None
    """

    @app.route('/update_my_profile', methods=['GET', 'POST'])
    @login_required
    def update_my_profile():
        """
        The view function for the 'update_my_profile' route. This function handles both
        GET and POST requests. On GET requests, it retrieves the current user's details
        and pre-fills a form with these details. On POST requests, it validates the
        submitted form and updates the current user's details in the database.
        Requires the user to be logged in.
        """

        form = UpdateUserForm()

        # Load current data
        if request.method == 'GET':
            form.name.data = current_user.name
            form.username.data = current_user.username

        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify(result='error', message='This username is already taken. '
                                                       'Please choose another.')
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
        """
        The view function for the 'new_user' route. This function handles both
        GET and POST requests. On POST requests, it validates the submitted form
        and creates a new user in the database with the form data.
        On GET requests, it simply renders a form for creating a new user.
        Requires the user to be both logged in and an admin.
        """
        print("NEW USER:")
        form = NewUserForm()
        print(form.validate_on_submit())
        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if not existing_user:
                hashed_password = bcrypt.generate_password_hash(form.password.data)
                new_user_instance = User(
                    name=(form.name.data or "John/Jane Doe")
                    if form.name.data.strip() != "" else "John/Jane Doe",
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
        """
        The view function for the home route. This function renders the home page
        of the application.
        Does not require the user to be logged in.
        """

        return render_template('home.html')

    @app.route('/delete_user', methods=['POST'])
    @login_required
    @admin_required
    def delete_user():
        """
        The view function for the 'delete_user' route. This function handles POST requests.
        It deletes a specified user from the database.
        Requires the user to be both logged in and an admin.
        """

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
        """
        The view function for the 'update_user' route. This function handles POST requests.
        It updates a specified user's details in the database.
        Requires the user to be logged in.
        """

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
        """
        The view function for the 'admin' route. This function handles both GET and POST requests.
        On GET requests, it renders a page showing all users in the database.
        Requires the user to be both logged in and an admin.
        """

        all_users = User.query.all()
        return render_template('admin.html', user=current_user, all_users=all_users)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        The view function for the 'login' route. This function handles both GET and POST requests.
        On GET requests, it renders a login form.
        On POST requests, it validates the submitted form and logs the user in if the form data
        is valid.
        Does not require the user to be logged in.
        """

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
        """
        The view function for the 'dashboard' route. This function renders the user's dashboard.
        Requires the user to be logged in.
        """

        return render_template('dashboard.html', user=current_user)

    @app.route('/logout', methods=['GET', 'POST'])
    @login_required
    def logout():
        """
        The view function for the 'logout' route. This function handles both
        GET and POST requests.
        It logs out the current user and redirects them to the login page.
        Requires the user to be logged in.
        """

        logout_user()
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """
        The view function for the 'register' route. This function handles
        both GET and POST requests.
        On GET requests, it renders a registration form.
        On POST requests, it validates the submitted form and creates a
        new user in the database with the form data.
        Does not require the user to be logged in.
        """

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
