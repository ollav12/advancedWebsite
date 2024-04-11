from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField


class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    login = SubmitField('Login')
    next = HiddenField()

