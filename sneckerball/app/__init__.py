from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# setup the app
app = Flask(__name__)
# configure the app using config file
app.config.from_object(Config)

# setup the database
db = SQLAlchemy(app)
# setup the migrate functionality
migrate = Migrate(app, db)

# setup the Login manager
login = LoginManager(app)
login.login_view = 'login'

from app import routes, models, errors

# Register the API blueprint
from app.api import bp as api_bp
app.register_blueprint(api_bp, url_prefix='/api')