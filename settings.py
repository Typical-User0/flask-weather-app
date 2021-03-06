import os

from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

application = Flask(__name__)

application.secret_key = os.getenv('SECRET_KEY')

application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///weather.db'

Bootstrap(application)

db = SQLAlchemy(application)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(application)
login_manager.login_message = None

API_KEY = os.getenv('API_KEY')
