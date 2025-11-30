"""
Database initialization script.

This module demonstrates:
- File I/O operations
- SQL execution
- Database setup automation
"""

import pymysql
import logging
from pathlib import Path
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_database():
    """
    Initialize the database by running the schema.sql script.

    This function:
    1. Connects to MySQL server (without selecting a database)
    2. Creates the database if it doesn't exist
    3. Runs the schema.sql to create tables

    Returns:
        bool: True if successful, False otherwise
    """
    schema_file = Path(__file__).parent / 'schema.sql'

    try:
        # Connect without selecting a database first
        connection = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            charset='utf8mb4'
        )

        logger.info("Connected to MySQL server")

        with connection.cursor() as cursor:
            # Read and execute schema file
            with open(schema_file, 'r', encoding='utf-8') as f:
                schema_sql = f.read()

            # Split by semicolons and execute each statement
            statements = [stmt.strip() for stmt in schema_sql.split(';') if stmt.strip()]

            for statement in statements:
                logger.debug(f"Executing: {statement[:50]}...")
                cursor.execute(statement)

            connection.commit()
            logger.info("Database schema initialized successfully")

        connection.close()
        return True

    except FileNotFoundError:
        logger.error(f"Schema file not found: {schema_file}")
        return False

    except pymysql.Error as e:
        logger.error(f"Database error during initialization: {e}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {e}")
        return False


def verify_database():
    """
    Verify that the database and tables exist.

    Returns:
        bool: True if database is properly set up
    """
    try:
        connection = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            charset='utf8mb4'
        )

        with connection.cursor() as cursor:
            # Check if threat_intel_cache table exists
            cursor.execute("SHOW TABLES LIKE 'threat_intel_cache'")
            result = cursor.fetchone()

            if result:
                logger.info("✓ Database verification successful - threat_intel_cache table exists")

                # Show table info
                cursor.execute("DESCRIBE threat_intel_cache")
                columns = cursor.fetchall()
                logger.info(f"✓ Table has {len(columns)} columns")

                connection.close()
                return True
            else:
                logger.error("✗ threat_intel_cache table not found")
                connection.close()
                return False

    except pymysql.Error as e:
        logger.error(f"✗ Database verification failed: {e}")
        return False


if __name__ == '__main__':
    """
    Run this script directly to initialize the database.

    Usage:
        python -m models.init_db
    """
    print("=" * 60)
    print("Threat Intel DB Initialization")
    print("=" * 60)

    logger.info("Starting database initialization...")

    if init_database():
        logger.info("✓ Database initialized successfully")

        if verify_database():
            logger.info("✓ Database verification passed")
            print("\n✅ Database is ready to use!")
        else:
            logger.error("✗ Database verification failed")
            print("\n❌ Database setup incomplete")
    else:
        logger.error("✗ Database initialization failed")
        print("\n❌ Database initialization failed")

    print("=" * 60)
