from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Optional
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from functools import wraps
from flask import abort

SQLALCHEMY_TRACK_MODIFICATIONS = False

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


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
    # print(User.query.get(int(user_id)))
    # print(User.username)
    # print(User.name)
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    name: str = db.Column(db.String(40))
    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    # email: str = db.Column(db.String(100), nullable=True)
    admin: bool = db.Column(db.Integer, nullable=False, default=0)
    blocked: bool = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self,
                 username: str,
                 name: str,
                 # email: str = "johndoe@somewhere.com",
                 password,
                 admin: bool = False,
                 blocked: bool = False
                 ):
        self.username = username
        # self.email = email
        self.name = name
        self.password = password
        self.admin = admin
        self.blocked = blocked


class NewUserForm(FlaskForm):
    name = StringField(validators=[
        Length(min=3, max=40)], render_kw={"placeholder": "Name"})

    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    admin = BooleanField(validators=[Optional()])

    blocked = BooleanField(validators=[Optional()])

    submit = SubmitField('Add User')


@app.route('/new_user', methods=['GET', 'POST'])
@admin_required
@login_required
def new_user():
    form = NewUserForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            name=form.name.data,
            username=form.username.data,
            password=hashed_password,
            admin=form.admin.data,
            blocked=form.blocked.data)
        db.session.add(new_user)
        try:
            db.session.commit()
            return redirect(url_for('admin'))
        except IntegrityError:
            db.session.rollback()
            return "A felhasználónév már foglalt. Kérjük, válasszon másikat.", 400
    return render_template('new_user.html', form=form)


class RegisterForm(FlaskForm):
    name = StringField(validators=[
        Length(min=3, max=40)], render_kw={"placeholder": "Name"})

    # email = StringField(validators=[
    #     Length(min=8)], render_kw={"placeholder": "Email"})

    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    @staticmethod
    def validate_username(username,
                          name
                          ):
        # print(email.data)
        # print(f"EXTRA: {username.data.get('username')}")
        # print(f"EXTRA: {name.data}")
        existing_user_username = User.query.filter_by(
            username=name.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
        else:
            print("user not exists yet.")


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


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
    admin: int = int(request.form.get('admin'))

    # email = str(request.form.get('email'))

    user = User.query.get(user_id)
    if user:
        user.name = new_name
        user.username = new_username
        user.blocked = blocked
        # user.email = email
        user.admin = admin
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
        # print("=" * 50)
        # print("Logging in user:")
        # print(f"user id: {User.query.filter_by(username=form.username.data).first()}")
        # print(f"user name: {user.name}({user.username})")
        # print(f"user blocked: {bool(user.blocked)}")
        # print("=" * 50)
        if user and not blocked:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
        # print(user)
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
        new_user = User(username=form.username.data,
                        name=form.name.data,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
