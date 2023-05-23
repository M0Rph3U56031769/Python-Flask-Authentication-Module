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
            raise ValidationError('Ez a felhasználónév már foglalt. Kérjük, válasszon másikat.')


class UpdateUserForm(FlaskForm):
    name = StringField(validators=[
        Length(min=3, max=40)], render_kw={"placeholder": "Name"})

    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Update User')
