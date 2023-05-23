# app.py
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager

app = Flask(__name__)

# Initiate login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'thisisasecretkey'

bcrypt = Bcrypt(app)

# Import here to avoid circular import
from features import models

models.db.init_app(app)

# Define routes
from features import routes  # Move import statement here

routes.define_routes(app, bcrypt)

if __name__ == "__main__":
    app.run(debug=True)
