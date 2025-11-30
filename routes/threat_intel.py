"""
Threat Intelligence routes blueprint.

This module demonstrates:
- Blueprint pattern for modular routing
- Route decorators
- Request handling and validation
- Template rendering
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for
import logging

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

    This route will:
    1. Validate the IP address
    2. Check cache for existing data
    3. Query threat intel APIs if needed
    4. Display aggregated results

    Returns:
        Rendered template with threat intel results or error
    """
    ip_address = request.form.get('ip_address', '').strip()

    logger.info(f"Lookup requested for IP: {ip_address}")

    # Validation and processing will be implemented in later tasks
    # For now, just acknowledge the request
    flash(f"Lookup functionality coming soon for IP: {ip_address}", "info")

    return redirect(url_for('threat_intel.index'))


@threat_intel_bp.route('/about', methods=['GET'])
def about():
    """
    Display information about the application.

    Returns:
        Rendered template for the about page
    """
    return render_template('threat_intel/about.html')
