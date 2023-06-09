# app.py
"""
This is the app.py module, responsible for initializing the Flask application.

Major functions include:

Creating a Flask application instance (app)
Initializing the LoginManager, which handles user sessions
Setting up CORS in the app, which ensures the app securely handles requests from different origins
Establishing database connection via SQLAlchemy
Setting up a secret key for encryption
Initializing Bcrypt, which handles password hashing
Connecting the application with models using SQLAlchemy's init_app() function
Defining routes within the application
This module is primarily used to run the Flask application.

The command app.run(debug=True) runs the application in a local development environment, with
debugging mode turned on.
"""

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager
from features import models
from features import routes
from features.login_manager import login_manager  # Add this line

app = Flask(__name__)

# Initiate login manager
login_manager.init_app(app)
login_manager.login_view = 'login'

CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# Change the key!!!
app.config['SECRET_KEY'] = 'thisisasecretkey'

bcrypt = Bcrypt(app)

models.db.init_app(app)

# Define routes

routes.define_routes(app, bcrypt)

if __name__ == "__main__":
    app.run(debug=True)
