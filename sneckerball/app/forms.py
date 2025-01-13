from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
import sqlalchemy as sa
from app import db
from app.models import User, Snackbar

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = db.session.scalar(sa.select(User).where(
            User.username == username.data))
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = db.session.scalar(sa.select(User).where(
            User.email == email.data))
        if user is not None:
            raise ValidationError('Please use a different email address.')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = db.session.scalar(sa.select(User).where(
                User.username == username.data
                ))
            if user is not None:
                raise ValidationError('Please use a different username.')

class EditSnackbarForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    about = TextAreaField('About', validators=[Length(min=0, max=140)])
    submit = SubmitField('Edit  ')
    
    def __init__(self, original_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_name = original_name

    def validate_name(self, name):
        if name.data  != self.original_name:
            snackbar = db.session.scalar(sa.select(Snackbar).where(
                Snackbar.name == name.data
                ))
            if snackbar is not None:
                raise ValidationError('Please use a different name.')


class AddSnackbarForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    about = TextAreaField('About', validators=[Length(min=0, max=140)])
    submit = SubmitField('Add')

    def validate_name(self, name):
        snackbar = db.session.scalar(sa.select(Snackbar).where(
            Snackbar.name == name.data))
        if snackbar is not None:
            raise ValidationError('Please use a different name.')


class ReviewForm(FlaskForm):
    body = TextAreaField('Say something', validators=[
        DataRequired(), Length(min=1, max=140)])
    submit = SubmitField('Submit')