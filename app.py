"""
Main Flask application entry point for Threat Intel Lookup App.

This module demonstrates:
- Application factory pattern for Flask
- Blueprint registration for modular routing
- Configuration management
- Error handling
"""

from flask import Flask, render_template
from config import Config
import logging


def create_app(config_class=Config):
    """
    Application factory function.

    This pattern allows for:
    - Easy testing with different configurations
    - Multiple instances of the app
    - Better organization and modularity

    Args:
        config_class: Configuration class to use (default: Config)

    Returns:
        Flask: Configured Flask application instance
    """
    # Initialize Flask app
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config_class)
    app.secret_key = config_class.SECRET_KEY

    # Configure logging
    logging.basicConfig(
        level=logging.INFO if config_class.is_development() else logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger = logging.getLogger(__name__)
    logger.info(f"Starting Threat Intel Lookup App in {config_class.FLASK_ENV} mode")

    # Validate required configuration
    try:
        config_class.validate_required_config()
        logger.info("Configuration validated successfully")
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        if not config_class.is_development():
            raise

    # Register blueprints
    from routes.threat_intel import threat_intel_bp
    app.register_blueprint(threat_intel_bp)
    logger.info("Registered threat_intel blueprint")

    # Register error handlers
    register_error_handlers(app)

    # Configure Jinja2 settings
    configure_jinja(app)

    logger.info("Flask application initialized successfully")
    return app


def register_error_handlers(app: Flask) -> None:
    """
    Register custom error handlers for the application.

    Args:
        app: Flask application instance
    """
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors."""
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        return render_template('errors/500.html'), 500


def configure_jinja(app: Flask) -> None:
    """
    Configure Jinja2 template settings.

    Args:
        app: Flask application instance
    """
    # Enable auto-reload of templates in development
    app.jinja_env.auto_reload = Config.is_development()

    # Add custom filters or globals if needed
    app.jinja_env.globals.update({
        'app_name': 'Threat Intel Lookup',
        'app_version': '1.0.0-MVP'
    })


# Create the application instance
app = create_app()


if __name__ == '__main__':
    """
    Run the Flask development server.

    Note: In production, use a proper WSGI server like Gunicorn or uWSGI.
    """
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=Config.is_development()
    )
