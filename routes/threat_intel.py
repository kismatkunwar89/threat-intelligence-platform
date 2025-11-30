"""
Threat Intelligence routes blueprint.

This module demonstrates:
- Blueprint pattern for modular routing
- Route decorators
- Request handling and validation
- Template rendering
- Integration of all components
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
import logging
from utils.ip_validator import IPValidator, IPValidationError
from models.cache import CacheManager
from services.abuseipdb_client import AbuseIPDBClient
from services.otx_client import OTXClient
from utils.normalizer import (
    normalize_abuseipdb,
    normalize_otx,
    aggregate_threat_intel
)
from config import Config

# Create blueprint
threat_intel_bp = Blueprint(
    'threat_intel',
    __name__,
    url_prefix='/'
)

logger = logging.getLogger(__name__)


@threat_intel_bp.route('/', methods=['GET'])
def index():
    """
    Display the main IP lookup form.

    Returns:
        Rendered template for the index page
    """
    logger.info("Index page accessed")
    return render_template('threat_intel/index.html')


@threat_intel_bp.route('/lookup', methods=['POST'])
def lookup():
    """
    Handle IP address lookup submission.

    This route demonstrates:
    1. Input validation
    2. Cache checking
    3. API aggregation
    4. Error handling
    5. Template rendering

    Returns:
        Rendered template with threat intel results or error
    """
    ip_address = request.form.get('ip_address', '').strip()

    logger.info(f"Lookup requested for IP: {ip_address}")

    # Step 1: Validate IP address
    validator = IPValidator()
    try:
        normalized_ip = validator.normalize_ip(ip_address)
        logger.info(f"IP validated and normalized: {normalized_ip}")
    except IPValidationError as e:
        logger.warning(f"Invalid IP address submitted: {ip_address}")
        flash(f"Invalid IP address: {str(e)}", "error")
        return redirect(url_for('threat_intel.index'))

    # Step 2: Check cache
    logger.info(f"Checking cache for {normalized_ip}")
    cached_data = CacheManager.get_cache(normalized_ip)

    if cached_data and not cached_data.is_expired:
        logger.info(f"Cache hit for {normalized_ip}")
        flash("Results loaded from cache", "info")
        return render_template(
            'threat_intel/results.html',
            ip_address=normalized_ip,
            threat_data=cached_data.threat_data,
            from_cache=True,
            cache_expires=cached_data.time_remaining
        )

    # Step 3: Query threat intel APIs
    logger.info(f"Cache miss - querying threat intel APIs for {normalized_ip}")

    try:
        threat_data = _fetch_threat_intel(normalized_ip)

        # Step 4: Cache the results
        logger.info(f"Caching results for {normalized_ip}")
        CacheManager.set_cache(normalized_ip, threat_data)

        # Step 5: Render results
        return render_template(
            'threat_intel/results.html',
            ip_address=normalized_ip,
            threat_data=threat_data,
            from_cache=False
        )

    except Exception as e:
        logger.error(f"Error fetching threat intel for {normalized_ip}: {e}", exc_info=True)
        flash(f"Error fetching threat intelligence: {str(e)}", "error")
        return redirect(url_for('threat_intel.index'))


def _fetch_threat_intel(ip_address: str) -> dict:
    """
    Fetch and aggregate threat intelligence from multiple sources.

    This function demonstrates:
    - Multiple API calls
    - Error handling for partial failures
    - Data aggregation

    Args:
        ip_address: Validated IP address

    Returns:
        dict: Aggregated threat intelligence data
    """
    normalized_responses = []

    # Fetch from AbuseIPDB
    try:
        if Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != "your_abuseipdb_api_key_here":
            logger.info(f"Querying AbuseIPDB for {ip_address}")
            abuse_client = AbuseIPDBClient()
            abuse_response = abuse_client.get_ip_reputation(ip_address)
            normalized_abuse = normalize_abuseipdb(abuse_response)
            normalized_responses.append(normalized_abuse)
            logger.info("AbuseIPDB data fetched successfully")
        else:
            logger.warning("AbuseIPDB API key not configured - skipping")
    except Exception as e:
        logger.error(f"Error fetching from AbuseIPDB: {e}")
        # Continue with other sources

    # Fetch from AlienVault OTX
    try:
        if Config.OTX_API_KEY and Config.OTX_API_KEY != "your_otx_api_key_here":
            logger.info(f"Querying AlienVault OTX for {ip_address}")
            otx_client = OTXClient()
            otx_response = otx_client.get_ip_reputation(ip_address)
            normalized_otx = normalize_otx(otx_response)
            normalized_responses.append(normalized_otx)
            logger.info("OTX data fetched successfully")
        else:
            logger.warning("OTX API key not configured - skipping")
    except Exception as e:
        logger.error(f"Error fetching from OTX: {e}")
        # Continue with available data

    # Check if we got any data
    if not normalized_responses:
        raise Exception("No threat intelligence data available. Please configure API keys.")

    # Aggregate the responses
    logger.info(f"Aggregating {len(normalized_responses)} threat intel sources")
    aggregated_data = aggregate_threat_intel(normalized_responses)

    return aggregated_data


@threat_intel_bp.route('/about', methods=['GET'])
def about():
    """
    Display information about the application.

    Returns:
        Rendered template for the about page
    """
    return render_template('threat_intel/about.html')
