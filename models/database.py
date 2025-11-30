"""
Database connection module using PyMySQL.

This module demonstrates:
- Context managers (__enter__ and __exit__)
- Connection pooling
- Exception handling
- Resource management
"""

import pymysql
from pymysql.cursors import DictCursor
from contextlib import contextmanager
from typing import Optional, Dict, Any
import logging
from config import Config

logger = logging.getLogger(__name__)


class DatabaseConnectionError(Exception):
    """Custom exception for database connection errors."""
    pass


class DatabaseConnection:
    """
    Database connection manager with context manager support.

    This class demonstrates the context manager protocol (__enter__ and __exit__)
    for automatic resource management.

    Example usage:
        with DatabaseConnection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cache")
            results = cursor.fetchall()
    """

    def __init__(self):
        """Initialize database connection parameters from config."""
        self.host = Config.DB_HOST
        self.port = Config.DB_PORT
        self.user = Config.DB_USER
        self.password = Config.DB_PASSWORD
        self.database = Config.DB_NAME
        self.connection: Optional[pymysql.connections.Connection] = None

    def __enter__(self) -> pymysql.connections.Connection:
        """
        Enter the context manager - establish database connection.

        Returns:
            pymysql.connections.Connection: Active database connection

        Raises:
            DatabaseConnectionError: If connection fails
        """
        try:
            self.connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                cursorclass=DictCursor,  # Return results as dictionaries
                autocommit=False,
                charset='utf8mb4'
            )
            logger.debug(f"Database connection established to {self.host}:{self.port}")
            return self.connection

        except pymysql.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise DatabaseConnectionError(f"Database connection failed: {e}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the context manager - close database connection.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred

        Returns:
            bool: False to propagate exceptions, True to suppress them
        """
        if self.connection:
            if exc_type is not None:
                # Rollback on error
                self.connection.rollback()
                logger.warning(f"Transaction rolled back due to {exc_type.__name__}")
            else:
                # Commit on success
                self.connection.commit()
                logger.debug("Transaction committed successfully")

            self.connection.close()
            logger.debug("Database connection closed")

        return False  # Propagate exceptions


class ConnectionPool:
    """
    Simple connection pool implementation.

    This demonstrates:
    - Singleton pattern for connection pool
    - Connection reuse for efficiency
    - Resource management
    """

    _instance: Optional['ConnectionPool'] = None
    _pool: list = []
    _pool_size: int = 5

    def __new__(cls):
        """Implement singleton pattern for connection pool."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_pool()
        return cls._instance

    def _initialize_pool(self):
        """Initialize the connection pool with configured size."""
        logger.info(f"Initializing connection pool with {self._pool_size} connections")
        # For simplicity, we'll create connections on-demand rather than pre-allocating
        self._pool = []

    @contextmanager
    def get_connection(self):
        """
        Get a connection from the pool (context manager).

        Yields:
            pymysql.connections.Connection: Database connection

        Example:
            pool = ConnectionPool()
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
        """
        # For MVP, we'll use simple connection without actual pooling
        # In production, implement connection reuse logic
        with DatabaseConnection() as conn:
            yield conn


@contextmanager
def get_db_connection():
    """
    Convenience function to get a database connection.

    This is a context manager that automatically handles connection lifecycle.

    Yields:
        pymysql.connections.Connection: Database connection

    Example:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cache WHERE ip_address = %s", (ip,))
            result = cursor.fetchone()
    """
    with DatabaseConnection() as conn:
        yield conn


def test_connection() -> bool:
    """
    Test the database connection.

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 as test")
            result = cursor.fetchone()
            logger.info(f"Database connection test successful: {result}")
            return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False
