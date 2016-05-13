import logging

from flask.app import Flask
from flask_admin.base import Admin
from flask_admin.contrib.sqla.view import ModelView
from flask_sqlalchemy import SQLAlchemy

from mittn.fuzzer.fuzzing import Issue


def build_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/musttu/Code/projects/cs/cs/repo.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    db = SQLAlchemy(app)

    app.secret_key = 'super secret key'

    admin = Admin(app, name='Fuzz', template_mode='bootstrap3')

    admin.add_view(ModelView(Issue, db.session))

    logging.basicConfig(level=logging.DEBUG)

    return app


if __name__ == '__main__':
    wsgi_app = build_app()
    wsgi_app.run(host='0.0.0.0', port=8000)
