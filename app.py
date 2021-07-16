from flask import render_template, request, redirect, url_for, flash
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import UnmappedInstanceError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

from forms import LoginForm, RegisterForm
from get_city_info import get_info
from settings import application, login_manager
from models import db, User, City


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# main page
@application.route('/')
@login_required
def index():
    if request.method == 'GET':
        cities_info = [
            get_info(city.name, city.id, current_user) for city in City.query.filter_by(user_id=current_user.id)
        ]

        return render_template('index.html', weathers=cities_info, user=current_user)


@application.route('/lang=<lang>')
def change_lang(lang):
    user = current_user
    if user.is_authenticated:
        if lang != 'ru' and lang != 'en':
            return redirect(url_for('index'))

        elif user.locale == lang:
            flash('You are already changed on this language')
            return redirect(url_for('index'))

        elif lang == 'ru' or lang == 'en':
            user.locale = lang
            db.session.commit()
            cities = [city for city in City.query.filter_by(user_id=user.id)]
            if cities:
                for city in cities:
                    city.name = get_info(city.name, city.id, current_user)['city']
                try:
                    db.session.commit()

                except IntegrityError:
                    db.session.rollback()
                    flash("The city has already been added to the list!")
                    return redirect(url_for('index'))
            return redirect(url_for('index'))
        return redirect(url_for('index'))
    return redirect(url_for('index'))


@application.route('/login', methods=['POST', 'GET'])
def login():
    # checking if user is logged in
    if current_user.is_authenticated:
        flash('You are already signed in')
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

            flash('Incorrect password or user!')
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
        flash('You are already signed in')
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

            new_user = User(username=form.username.data, password=hashed_password,)

            try:
                db.session.add(new_user)
                db.session.commit()

            except IntegrityError as err:
                flash('This username is already taken!')
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


# updates page with results of user request
@application.route('/add', methods=['POST', 'GET'])
@login_required
def add_city():
    if request.method == 'POST':
        try:
            city_name = request.form['city_name'].lower()
            result = get_info(city_name, 1, current_user)
            if type(result) == dict:
                db.session.add(City(name=result['city'], user_id=current_user.id))
                db.session.commit()
                return redirect(url_for('index'))

        except IntegrityError:
            db.session.rollback()
            flash("The city has already been added to the list!")
            return redirect(url_for('index'))
    return redirect(url_for('index'))


if __name__ == '__main__':
    application.run(host='0.0.0.0')
