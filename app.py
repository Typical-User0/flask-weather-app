from flask import Flask, render_template, request, redirect, url_for, flash
import sys
import json
import requests
import datetime
from flask_babel import Babel, gettext
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from sqlalchemy.orm.exc import UnmappedInstanceError
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# configure flask application
application = Flask(__name__)

application.secret_key = '&C&;/T;CEO#X%~5EgEjl&HHiwn8f8j#i:hIjBXBEF!0]O9vf)]Hsp)8`$0PnrbG9\omRc1<=O:9b=P.sGzI/1u2Rr<i2]FffLe=V\'hxIyk\~~[#b+T%W*Fl6eYtXN/SL-/7{J:+C!XP(q5qr#N<qXpEKbo?J_P3@CUf~"%YiHGU"oDCED6>N>#Kt`ya^u`%c+cb\ez.z~AB?{<Z(/:Pb*;goY!JeS?n5,$5@.4PSz5?|yZ1j/:%;t2RMts!\r}P<'

application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///weather.db'
babel = Babel(application)
Bootstrap(application)
db = SQLAlchemy(application)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(application)
login_manager.login_message = None


# representation of our table in DB
class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
    db.UniqueConstraint(name, user_id)

    def __repr__(self):
        return f'{self.id}: {self.name} user - {self.user_id}'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text(60), nullable=False, unique=True)
    password = db.Column(db.Text(256), nullable=False)
    locale = db.Column(db.Text(2), default='en')

    def __repr__(self):
        return f'{self.id} - {self.username} - {self.password} - {self.locale}'


class LoginForm(FlaskForm):
    username = StringField(gettext('Username'), validators=[InputRequired(), Length(min=2, max=60)])
    password = PasswordField(gettext('Password'), validators=[InputRequired(), Length(min=8, max=256)])
    remember_me = BooleanField(gettext('remember me'))


class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[InputRequired(message=gettext('Please, write the username!')), Length(min=2, max=60)]
    )

    password = PasswordField(gettext('Password'), validators=[InputRequired(), Length(min=8, max=256)])
    repeat_password = PasswordField(gettext('Repeat the password'), validators=[InputRequired(), Length(min=8, max=256)])

    def __repr__(self):
        return f'users: {self.id} - {self.username}'


@babel.localeselector
def get_locale():
    # if a user is logged in, use the locale from the user settings
    if current_user.is_authenticated:
        return current_user.locale
    return request.accept_languages.best_match(['en', 'ru'])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# main page
@application.route('/')
@login_required
def index():
    if request.method == 'GET':
        print(User.query.all())
        print(City.query.all())
        cities_info = [
            get_info(city.name, city.id) for city in City.query.filter_by(user_id=current_user.id)
        ]

        return render_template('index.html', weathers=cities_info, user=current_user)


@application.route('/lang=<lang>')
def change_lang(lang):
    user = current_user
    if user.is_authenticated:
        if lang != 'ru' and lang != 'en':
            return redirect(url_for('index'))

        elif user.locale == lang:
            flash(gettext('You are already changed on this language'))
            return redirect(url_for('index'))

        elif lang == 'ru' or lang == 'en':
            user.locale = lang
            db.session.commit()
            cities = [city for city in City.query.filter_by(user_id=user.id)]
            if cities:
                for city in cities:
                    city.name = get_info(city.name, city.id)['city']
                try:
                    db.session.commit()

                except IntegrityError:
                    db.session.rollback()
                    flash(gettext("The city has already been added to the list!"))
                    return redirect(url_for('index'))
            return redirect(url_for('index'))
        return redirect(url_for('index'))
    return redirect(url_for('index'))


@application.route('/login', methods=['POST', 'GET'])
def login():
    # checking if user is logged in
    if current_user.is_authenticated:
        flash(gettext('You are already signed in'))
        return redirect(url_for('index'))
    # if not
    else:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(pwhash=user.password, password=form.password.data):
                    login_user(user, remember=form.remember_me.data)
                    return redirect(url_for('index'))

            flash(gettext('Incorrect password or user!'))
            return redirect(url_for('login'))
        return render_template('login.html', form=form, user=current_user)


# log out page
@application.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# sign up page
@application.route('/signup', methods=['POST', 'GET'])
def signup():
    # checking if user logged in
    if current_user.is_authenticated:
        flash(gettext('You are already signed in'))
        return redirect(url_for('index'))
    # if not:
    else:
        form = RegisterForm()
        if form.validate_on_submit():
            if form.repeat_password.data == form.password.data:
                hashed_password = generate_password_hash(form.password.data, method='sha256')
            else:
                flash('Passwords don\'t match ')
                return render_template('signup.html', form=form)

            new_user = User(username=form.username.data,
                            password=hashed_password,
                            )
            try:
                db.session.add(new_user)
                db.session.commit()

            except IntegrityError as err:
                print(err)
                flash(gettext('This username is already taken!'))
                return redirect(url_for('signup'))

            return redirect(url_for('index'))
        return render_template('signup.html', form=form, user=current_user)


# deletes cards
@application.route('/delete/<city_id>', methods=['GET', 'POST'])
@login_required
def delete(city_id):
    try:
        city = City.query.filter_by(user_id=current_user.id, id=city_id).first()
        db.session.delete(city)
        db.session.commit()
    except UnmappedInstanceError:
        return redirect(url_for('index'))
    return redirect(url_for('index'))


# getting information about city with API
def get_info(city, city_id):
    api_key = 'c5c4c63610e2803528ae1d62a7060bca'

    # making request to the API url
    r = requests.get(
        f'https://api.openweathermap.org/data/2.5/weather?q={city}&units=metric&lang='
        f'{current_user.locale}&appid={api_key}'
    )

    # formatting data to python dictionary
    weather_dict = json.loads(r.text)

    # if city does not exist
    if weather_dict['cod'] == '404':
        flash(gettext("The city doesn't exist!"))
        return redirect(url_for('index'))

    # retrieving and formatting the necessary data
    temp = round(weather_dict['main']['temp'])
    city_name = weather_dict['name']
    local_time = (datetime.datetime.utcnow() + datetime.timedelta(seconds=weather_dict['timezone'])).strftime("%H")
    description = weather_dict['weather'][0]['description']
    # checking for day state
    day_state = None

    if 6 <= int(local_time) <= 16:
        day_state = 'day'
    elif 17 <= int(local_time) <= 23:
        day_state = 'evening-morning'
    elif 0 <= int(local_time) <= 5:
        day_state = 'night'

    return {'time': local_time,
            'city': city_name,
            'temp': temp,
            'day_state': day_state,
            'city_id': city_id,
            'description': description,
            }


# updates page with results of user request
@application.route('/add', methods=['POST', 'GET'])
@login_required
def add_city():
    if request.method == 'POST':
        try:
            city_name = request.form['city_name'].lower()
            result = get_info(city_name, 1)
            if type(result) == dict:
                db.session.add(City(name=result['city'], user_id=current_user.id))
                db.session.commit()
                return redirect(url_for('index'))

        except IntegrityError:
            db.session.rollback()
            flash(gettext("The city has already been added to the list!"))
            return redirect(url_for('index'))
    return redirect(url_for('index'))


if __name__ == '__main__':
    application.run(host='0.0.0.0')
