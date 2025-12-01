"""
Configuration module for Threat Intel Lookup application.

This module demonstrates:
- OOP principles with a Config class
- Environment variable management using python-dotenv
- Property decorators for computed values
- Exception handling for missing configuration
"""

import os
from typing import Optional
from dotenv import load_dotenv


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass


class Config:
    """
    Configuration class that loads and validates environment variables.

    This class uses the Singleton-like pattern via class methods to ensure
    consistent configuration across the application.
    """

    # Load environment variables from .env file
    load_dotenv()

    # Flask Configuration
    FLASK_APP: str = os.getenv('FLASK_APP', 'app.py')
    FLASK_ENV: str = os.getenv('FLASK_ENV', 'development')
    SECRET_KEY: str = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

    # Database Configuration
    DB_HOST: str = os.getenv('DB_HOST', 'localhost')
    DB_PORT: int = int(os.getenv('DB_PORT', '3306'))
    DB_USER: Optional[str] = os.getenv('DB_USER')
    DB_PASSWORD: Optional[str] = os.getenv('DB_PASSWORD')
    DB_NAME: str = os.getenv('DB_NAME', 'threat_intel_db')

    # API Keys
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv('ABUSEIPDB_API_KEY')
    OTX_API_KEY: Optional[str] = os.getenv('OTX_API_KEY')
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv('VIRUSTOTAL_API_KEY')
    GREYNOISE_API_KEY: Optional[str] = os.getenv('GREYNOISE_API_KEY')

    # Cache Configuration
    CACHE_TTL_SECONDS: int = int(os.getenv('CACHE_TTL_SECONDS', '3600'))

    # API Configuration
    API_TIMEOUT_SECONDS: int = int(os.getenv('API_TIMEOUT_SECONDS', '10'))
    MAX_RETRIES: int = int(os.getenv('MAX_RETRIES', '3'))

    @classmethod
    def get_database_uri(cls) -> str:
        """
        Construct database connection URI.

        Returns:
            str: MySQL connection URI

        Raises:
            ConfigurationError: If required database credentials are missing
        """
        if not cls.DB_USER or not cls.DB_PASSWORD:
            raise ConfigurationError(
                "Database credentials (DB_USER, DB_PASSWORD) must be set in environment variables"
            )

        return f"mysql://{cls.DB_USER}:{cls.DB_PASSWORD}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"

    @classmethod
    def get_database_config(cls) -> dict:
        """
        Get database configuration as a dictionary for mysql.connector.

        Returns:
            dict: Database configuration parameters

        Raises:
            ConfigurationError: If required database credentials are missing
        """
        if not cls.DB_USER or not cls.DB_PASSWORD:
            raise ConfigurationError(
                "Database credentials (DB_USER, DB_PASSWORD) must be set in environment variables"
            )

        return {
            'host': cls.DB_HOST,
            'port': cls.DB_PORT,
            'user': cls.DB_USER,
            'password': cls.DB_PASSWORD,
            'database': cls.DB_NAME
        }

    @classmethod
    def validate_required_config(cls) -> None:
        """
        Validate that all required configuration values are present.

        Raises:
            ConfigurationError: If any required configuration is missing
        """
        # Required configurations
        required_configs = {
            'DB_USER': cls.DB_USER,
            'DB_PASSWORD': cls.DB_PASSWORD,
            'ABUSEIPDB_API_KEY': cls.ABUSEIPDB_API_KEY,
            'OTX_API_KEY': cls.OTX_API_KEY
        }

        # Use comprehension to find missing configs (Pythonic!)
        missing_configs = [key for key, value in required_configs.items() if not value]

        if missing_configs:
            raise ConfigurationError(
                f"Missing required configuration: {', '.join(missing_configs)}. "
                f"Please set these in your .env file or environment variables."
            )

    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development mode."""
        return cls.FLASK_ENV == 'development'

    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production mode."""
        return cls.FLASK_ENV == 'production'

    @classmethod
    def display_config_summary(cls) -> dict:
        """
        Get a safe summary of configuration (without secrets).

        Returns:
            dict: Configuration summary with masked sensitive values
        """
        return {
            'flask_env': cls.FLASK_ENV,
            'database_host': cls.DB_HOST,
            'database_port': cls.DB_PORT,
            'database_name': cls.DB_NAME,
            'cache_ttl': cls.CACHE_TTL_SECONDS,
            'api_timeout': cls.API_TIMEOUT_SECONDS,
            'max_retries': cls.MAX_RETRIES,
            'abuseipdb_configured': bool(cls.ABUSEIPDB_API_KEY),
            'otx_configured': bool(cls.OTX_API_KEY),
            'virustotal_configured': bool(cls.VIRUSTOTAL_API_KEY),
            'greynoise_configured': bool(cls.GREYNOISE_API_KEY)
        }


# Convenience function for getting config instance
def get_config() -> Config:
    """
    Get the application configuration.

    Returns:
        Config: Configuration instance
    """
    return Config
