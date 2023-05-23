"""
This is the forms.py module, primarily responsible for defining and validating forms in the Flask
application using Flask-WTF.

This module includes four form classes:

RegisterForm: This class defines the registration form with fields for 'name', 'username' and 'password',
and validates the inputs.

LoginForm: This class defines the login form with fields for 'username' and 'password', and a 'submit' button.

NewUserForm: This class defines the form for adding a new user with fields for 'name', 'username',
'password', 'admin' status and 'blocked' status. This form includes a unique username validation
method to prevent duplications.

UpdateUserForm: This class defines the form for updating user details. The fields are the same as
in the NewUserForm class excluding the 'admin' and 'blocked' status fields.

Each form field is defined with validators to handle required data constraints and length limitations.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms import SubmitField
from wtforms.validators import DataRequired, Length
from wtforms.validators import InputRequired, ValidationError, Optional

from features.models import User


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class NewUserForm(FlaskForm):
    name = StringField(validators=[
        Length(max=40)], render_kw={"placeholder": "Name"})

    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    admin = BooleanField(validators=[Optional()])

    blocked = BooleanField(validators=[Optional()])

    submit = SubmitField('Add User')

    @staticmethod
    def validate_username(form, field):
        print(form.username)
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('This username is already taken. Please choose another.')


class UpdateUserForm(FlaskForm):
    name = StringField(validators=[
        Length(min=3, max=40)], render_kw={"placeholder": "Name"})

    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Update User')
