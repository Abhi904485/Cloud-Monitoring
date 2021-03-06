from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired("Enter your Username"), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired("Enter your Email"), Email()])
    password = PasswordField('Password', validators=[DataRequired("Enter your password")])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired("Enter your Email"), Email()])
    password = PasswordField('Password', validators=[DataRequired("Enter your Password")])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
