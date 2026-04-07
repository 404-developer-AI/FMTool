import os

from flask import Flask

from config import Config


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="../static",
    )
    app.config.from_object(Config)

    # Ensure instance directories exist
    os.makedirs(app.config["DATABASE_PATH"].rsplit(os.sep, 1)[0], exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Register blueprints
    from app.routes.main import main_bp

    app.register_blueprint(main_bp)

    return app
