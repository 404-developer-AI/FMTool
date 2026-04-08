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

    # Load local config overrides (Sophos credentials, etc.)
    local_config = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.local.py")
    if os.path.exists(local_config):
        app.config.from_pyfile(local_config)

    # Ensure instance directories exist
    os.makedirs(app.config["DATABASE_PATH"].rsplit(os.sep, 1)[0], exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Initialize database
    from app.models.database import init_db

    init_db(app.config["DATABASE_PATH"])

    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.overview import overview_bp
    from app.routes.sophos import sophos_bp
    from app.routes.upload import upload_bp
    from app.routes.migrate import migrate_bp
    from app.routes.activity_log import activity_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(overview_bp)
    app.register_blueprint(sophos_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(migrate_bp)
    app.register_blueprint(activity_bp)

    return app
