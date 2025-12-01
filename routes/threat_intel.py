"""
Threat Intelligence routes blueprint.

This module demonstrates:
- Blueprint pattern for modular routing
- Route decorators
- Request handling and validation
- Template rendering
- Integration of all components
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, make_response, send_file
import json
import csv
import io
from datetime import datetime
import logging
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from utils.ip_validator import IPValidator, IPValidationError
from models.cache import CacheManager
from models.threat_intel_result import ThreatIntelResult
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


def _fetch_threat_intel(ip_address: str) -> ThreatIntelResult:
    """
    Fetch and aggregate threat intelligence from multiple sources.

    This function demonstrates:
    - Multiple API calls
    - Error handling for partial failures
    - Data aggregation

    Args:
        ip_address: Validated IP address

    Returns:
        ThreatIntelResult: Canonical dataclass with aggregated threat intelligence
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


@threat_intel_bp.route('/lookup/<ip>/export/json', methods=['GET'])
def export_json(ip: str):
    """
    Export threat intelligence data as JSON.

    This route provides a downloadable JSON file containing all threat
    intelligence data for the specified IP address.

    Args:
        ip: IP address to export

    Returns:
        JSON file download response
    """
    logger.info(f"JSON export requested for IP: {ip}")

    try:
        # Validate IP
        validator = IPValidator()
        normalized_ip = validator.normalize_ip(ip)

        # Get from cache or fetch fresh
        cached = CacheManager.get_cache(normalized_ip)
        if cached and not cached.is_expired:
            logger.info(f"Using cached data for JSON export: {normalized_ip}")
            data = cached.threat_data
        else:
            logger.info(f"Fetching fresh data for JSON export: {normalized_ip}")
            data = _fetch_threat_intel(normalized_ip)
            CacheManager.set_cache(normalized_ip, data)

        # Convert to dict if dataclass
        if hasattr(data, 'to_dict'):
            data_dict = data.to_dict()
        else:
            data_dict = data

        # Create JSON response with pretty formatting
        json_str = json.dumps(data_dict, indent=2, ensure_ascii=False)
        response = make_response(json_str)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=threat_intel_{normalized_ip}.json'

        logger.info(f"JSON export completed for {normalized_ip}")
        return response

    except IPValidationError as e:
        logger.error(f"Invalid IP for JSON export: {ip}")
        return jsonify({"error": f"Invalid IP address: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Error exporting JSON for {ip}: {e}", exc_info=True)
        return jsonify({"error": f"Export failed: {str(e)}"}), 500


@threat_intel_bp.route('/lookup/<ip>/export/csv', methods=['GET'])
def export_csv(ip: str):
    """
    Export threat intelligence data as CSV (flattened key-value format).

    The CSV contains two columns: Field and Value, with all data flattened
    from the nested structure. Lists are joined with pipes (|) for readability.

    Args:
        ip: IP address to export

    Returns:
        CSV file download response
    """
    logger.info(f"CSV export requested for IP: {ip}")

    try:
        # Validate IP
        validator = IPValidator()
        normalized_ip = validator.normalize_ip(ip)

        # Get from cache or fetch fresh
        cached = CacheManager.get_cache(normalized_ip)
        if cached and not cached.is_expired:
            logger.info(f"Using cached data for CSV export: {normalized_ip}")
            data = cached.threat_data
        else:
            logger.info(f"Fetching fresh data for CSV export: {normalized_ip}")
            data = _fetch_threat_intel(normalized_ip)
            CacheManager.set_cache(normalized_ip, data)

        # Convert to dict if dataclass
        if hasattr(data, 'to_dict'):
            data_dict = data.to_dict()
        else:
            data_dict = data

        # Flatten data to key-value pairs
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Field', 'Value'])

        # Write each field
        for key, value in data_dict.items():
            if isinstance(value, list):
                # Join lists with pipe separator
                value_str = ' | '.join(str(v) for v in value) if value else ''
            elif isinstance(value, dict):
                # For nested dicts (like recommendation), format as key: value pairs
                value_str = ' | '.join(f"{k}: {v}" for k, v in value.items()) if value else ''
            elif value is None:
                value_str = 'N/A'
            else:
                value_str = str(value)

            writer.writerow([key, value_str])

        # Create CSV response
        csv_data = output.getvalue()
        response = make_response(csv_data)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=threat_intel_{normalized_ip}.csv'

        logger.info(f"CSV export completed for {normalized_ip}")
        return response

    except IPValidationError as e:
        logger.error(f"Invalid IP for CSV export: {ip}")
        return jsonify({"error": f"Invalid IP address: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Error exporting CSV for {ip}: {e}", exc_info=True)
        return jsonify({"error": f"Export failed: {str(e)}"}), 500


@threat_intel_bp.route('/lookup/<ip>/export/pdf', methods=['GET'])
def export_pdf(ip: str):
    """
    Export threat intelligence data as professional PDF report (1-2 pages).

    Generates a well-formatted PDF document with sections for:
    - Executive summary with risk assessment
    - Technical details (geo, ISP, reports)
    - Threat intelligence (categories, types, sources)
    - Actionable recommendation

    Args:
        ip: IP address to export

    Returns:
        PDF file download response
    """
    logger.info(f"PDF export requested for IP: {ip}")

    try:
        # Validate IP
        validator = IPValidator()
        normalized_ip = validator.normalize_ip(ip)

        # Get from cache or fetch fresh
        cached = CacheManager.get_cache(normalized_ip)
        if cached and not cached.is_expired:
            logger.info(f"Using cached data for PDF export: {normalized_ip}")
            data = cached.threat_data
        else:
            logger.info(f"Fetching fresh data for PDF export: {normalized_ip}")
            data = _fetch_threat_intel(normalized_ip)
            CacheManager.set_cache(normalized_ip, data)

        # Convert to dict if dataclass
        if hasattr(data, 'to_dict'):
            data_dict = data.to_dict()
        else:
            data_dict = data

        # Generate PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                               topMargin=0.75*inch, bottomMargin=0.75*inch)

        # Container for PDF elements
        elements = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#1a73e8'),
            spaceAfter=12,
            alignment=TA_CENTER
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1a73e8'),
            spaceAfter=10,
            spaceBefore=15
        )

        # Title
        elements.append(Paragraph("THREAT INTELLIGENCE REPORT", title_style))
        elements.append(Paragraph(f"IP Address: {normalized_ip}", styles['Normal']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))

        # Risk Assessment Section
        elements.append(Paragraph("RISK ASSESSMENT", heading_style))

        risk_score = data_dict.get('risk_score', 0)
        risk_level = "HIGH RISK" if risk_score >= 75 else "MEDIUM RISK" if risk_score >= 50 else "LOW RISK" if risk_score >= 25 else "CLEAN"
        risk_color = colors.red if risk_score >= 75 else colors.orange if risk_score >= 50 else colors.yellow if risk_score >= 25 else colors.green

        assessment_data = [
            ['Metric', 'Value'],
            ['Risk Score', f"{risk_score}/100"],
            ['Risk Level', risk_level],
            ['Malicious', 'YES' if data_dict.get('is_malicious') else 'NO'],
            ['Total Reports', str(data_dict.get('total_reports', 0))],
        ]

        assessment_table = Table(assessment_data, colWidths=[2.5*inch, 3.5*inch])
        assessment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a73e8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(assessment_table)
        elements.append(Spacer(1, 0.2*inch))

        # Technical Details Section
        elements.append(Paragraph("TECHNICAL DETAILS", heading_style))

        tech_data = [
            ['Field', 'Value'],
            ['Country', data_dict.get('country') or 'Unknown'],
            ['Country Code', data_dict.get('country_code') or 'N/A'],
            ['ISP', data_dict.get('isp') or 'Unknown'],
            ['Domain', data_dict.get('domain') or 'N/A'],
            ['Last Reported', data_dict.get('last_reported') or 'N/A'],
        ]

        tech_table = Table(tech_data, colWidths=[2.5*inch, 3.5*inch])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a73e8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(tech_table)
        elements.append(Spacer(1, 0.2*inch))

        # Threat Intelligence Section
        elements.append(Paragraph("THREAT INTELLIGENCE", heading_style))

        categories = data_dict.get('categories', [])
        threat_types = data_dict.get('threat_types', [])
        sources = data_dict.get('sources', [])

        intel_text = f"""
        <b>Data Sources:</b> {', '.join(sources) if sources else 'None'}<br/>
        <b>Categories:</b> {', '.join(categories[:10]) if categories else 'None'}<br/>
        <b>Threat Types:</b> {', '.join(threat_types[:10]) if threat_types else 'None'}
        """
        elements.append(Paragraph(intel_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))

        # Recommendation Section
        recommendation = data_dict.get('recommendation', {})
        if recommendation:
            elements.append(Paragraph("RECOMMENDATION", heading_style))

            rec_data = [
                ['Action', recommendation.get('action', 'N/A')],
                ['Priority', recommendation.get('priority', 'N/A')],
                ['Justification', recommendation.get('justification', 'N/A')],
            ]

            rec_table = Table(rec_data, colWidths=[2.5*inch, 3.5*inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a73e8')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(rec_table)

        # Footer
        elements.append(Spacer(1, 0.3*inch))
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                     textColor=colors.grey, alignment=TA_CENTER)
        elements.append(Paragraph(
            "Generated by Threat Intel Lookup | For authorized security operations only",
            footer_style
        ))

        # Build PDF
        doc.build(elements)

        # Return PDF
        buffer.seek(0)
        logger.info(f"PDF export completed for {normalized_ip}")
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'threat_intel_{normalized_ip}.pdf'
        )

    except IPValidationError as e:
        logger.error(f"Invalid IP for PDF export: {ip}")
        return jsonify({"error": f"Invalid IP address: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Error exporting PDF for {ip}: {e}", exc_info=True)
        return jsonify({"error": f"Export failed: {str(e)}"}), 500
