from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, BooleanField
from wtforms.validators import InputRequired, Length


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=60)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=256)])
    remember_me = BooleanField('remember me')


class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[InputRequired(message='Please, write the username!'), Length(min=2, max=60)]
    )

    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=256)])
    repeat_password = PasswordField('Repeat the password', validators=[InputRequired(), Length(min=8, max=256)])

    def __repr__(self):
        return f'users: {self.id} - {self.username}'
