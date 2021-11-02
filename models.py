from flask_login import UserMixin
from settings import db


# representation of our table in DB
class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    db.UniqueConstraint(name, user_id)

    def __repr__(self):
        return f'{self.id}: {self.name} user - {self.user_id}'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text(60), nullable=False, unique=True)
    password = db.Column(db.Text(256), nullable=False)

    def __repr__(self):
        return f'{self.id} - {self.username} - {self.password}'
