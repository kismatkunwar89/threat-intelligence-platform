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
from services.virustotal_client import VirusTotalClient
from services.greynoise_client import GreyNoiseClient
from utils.normalizer import (
    normalize_abuseipdb,
    normalize_otx,
    normalize_virustotal,
    normalize_greynoise,
    aggregate_threat_intel
)
from utils.mitre_mapper import map_to_mitre_attack
from utils.kill_chain_mapper import map_to_kill_chain
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
        logger.error(
            f"Error fetching threat intel for {normalized_ip}: {e}", exc_info=True)
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

    # Fetch from VirusTotal
    try:
        if Config.VIRUSTOTAL_API_KEY and Config.VIRUSTOTAL_API_KEY != "your_virustotal_api_key_here":
            logger.info(f"Querying VirusTotal for {ip_address}")
            vt_client = VirusTotalClient()
            vt_response = vt_client.check_ip(ip_address)
            if vt_response:  # May be None if rate limited
                normalized_vt = normalize_virustotal(vt_response)
                normalized_responses.append(normalized_vt)
                logger.info("VirusTotal data fetched successfully")
            else:
                logger.warning("VirusTotal rate limit or error - skipping")
        else:
            logger.warning("VirusTotal API key not configured - skipping")
    except Exception as e:
        logger.error(f"Error fetching from VirusTotal: {e}")
        # Continue with available data

    # Fetch from GreyNoise (Community API - no key required)
    try:
        logger.info(f"Querying GreyNoise for {ip_address}")
        gn_client = GreyNoiseClient()
        gn_response = gn_client.check_ip(ip_address)
        if gn_response:
            normalized_gn = normalize_greynoise(gn_response)
            normalized_responses.append(normalized_gn)
            logger.info(
                f"GreyNoise data fetched: classification={gn_response.get('classification', 'unknown')}")
        else:
            logger.warning("GreyNoise returned no data - skipping")
    except Exception as e:
        logger.error(f"Error fetching from GreyNoise: {e}")
        # Continue with available data

    # Check if we got any data
    if not normalized_responses:
        raise Exception(
            "No threat intelligence data available. Please configure API keys.")

    # Aggregate the responses
    logger.info(
        f"Aggregating {len(normalized_responses)} threat intel sources")
    aggregated_data = aggregate_threat_intel(normalized_responses)

    # Add MITRE ATT&CK mapping
    mitre_techniques = map_to_mitre_attack(aggregated_data.to_dict())
    aggregated_data.mitre_attack = mitre_techniques
    logger.info(f"Mapped to {len(mitre_techniques)} MITRE ATT&CK techniques")

    # Add Kill Chain mapping
    kill_chain_stages = map_to_kill_chain(aggregated_data.to_dict())
    aggregated_data.kill_chain_stages = kill_chain_stages
    logger.info(f"Mapped to {len(kill_chain_stages)} Kill Chain stages")

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
            logger.info(
                f"Fetching fresh data for JSON export: {normalized_ip}")
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
        response.headers[
            'Content-Disposition'] = f'attachment; filename=threat_intel_{normalized_ip}.json'

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
                value_str = ' | '.join(
                    f"{k}: {v}" for k, v in value.items()) if value else ''
            elif value is None:
                value_str = 'N/A'
            else:
                value_str = str(value)

            writer.writerow([key, value_str])

        # Create CSV response
        csv_data = output.getvalue()
        response = make_response(csv_data)
        response.headers['Content-Type'] = 'text/csv'
        response.headers[
            'Content-Disposition'] = f'attachment; filename=threat_intel_{normalized_ip}.csv'

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
        elements.append(
            Paragraph(f"IP Address: {normalized_ip}", styles['Normal']))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))

        # Risk Assessment Section with Visual Gauges
        elements.append(Paragraph("RISK ASSESSMENT", heading_style))

        risk_score = data_dict.get('risk_score', 0)
        confidence_score = data_dict.get('confidence_score', 0)
        risk_level = "HIGH RISK" if risk_score >= 75 else "MEDIUM RISK" if risk_score >= 50 else "LOW RISK" if risk_score >= 25 else "CLEAN"
        confidence_level = "VERY HIGH" if confidence_score >= 80 else "HIGH" if confidence_score >= 60 else "MEDIUM" if confidence_score >= 40 else "LOW"
        risk_color = colors.red if risk_score >= 75 else colors.orange if risk_score >= 50 else colors.yellow if risk_score >= 25 else colors.green
        conf_color = colors.green if confidence_score >= 80 else colors.cyan if confidence_score >= 60 else colors.orange if confidence_score >= 40 else colors.red

        # Create visual progress bars
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.graphics import renderPDF

        # Risk Score Bar
        risk_drawing = Drawing(400, 60)
        # Background bar
        risk_drawing.add(Rect(0, 30, 300, 20, fillColor=colors.lightgrey, strokeColor=colors.black))
        # Progress bar
        risk_drawing.add(Rect(0, 30, risk_score * 3, 20, fillColor=risk_color, strokeColor=None))
        # Label
        risk_drawing.add(String(150, 10, f"Risk Score: {risk_score}/100 - {risk_level}",
                               fontSize=12, fillColor=colors.black, textAnchor='middle'))

        # Confidence Score Bar
        conf_drawing = Drawing(400, 60)
        # Background bar
        conf_drawing.add(Rect(0, 30, 300, 20, fillColor=colors.lightgrey, strokeColor=colors.black))
        # Progress bar
        conf_drawing.add(Rect(0, 30, confidence_score * 3, 20, fillColor=conf_color, strokeColor=None))
        # Label
        conf_drawing.add(String(150, 10, f"Confidence: {confidence_score}% - {confidence_level}",
                               fontSize=12, fillColor=colors.black, textAnchor='middle'))

        elements.append(risk_drawing)
        elements.append(Spacer(1, 0.1*inch))
        elements.append(conf_drawing)
        elements.append(Spacer(1, 0.2*inch))

        # Assessment Table
        assessment_data = [
            ['Metric', 'Value'],
            ['Risk Score', f"{risk_score}/100"],
            ['Risk Level', risk_level],
            ['Confidence Score', f"{confidence_score}%"],
            ['Confidence Level', confidence_level],
            ['Malicious', 'YES' if data_dict.get('is_malicious') else 'NO'],
            ['Total Reports', str(data_dict.get('total_reports', 0))],
        ]

        assessment_table = Table(
            assessment_data, colWidths=[2.5*inch, 3.5*inch])
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
        <b>Categories:</b> {', '.join(categories[:10]) if categories else 'None'}<br/>
        <b>Threat Types:</b> {', '.join(threat_types[:10]) if threat_types else 'None'}
        """
        elements.append(Paragraph(intel_text, styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))

        # API Source Health Visual
        elements.append(Paragraph("<b>API Source Health:</b>", styles['Normal']))
        elements.append(Spacer(1, 0.05*inch))

        source_drawing = Drawing(400, 40)
        all_sources = ['AbuseIPDB', 'AlienVault OTX', 'VirusTotal', 'GreyNoise']
        x_pos = 0
        for i, api in enumerate(all_sources):
            source_active = api in sources
            # Draw box
            box_color = colors.green if source_active else colors.lightgrey
            source_drawing.add(Rect(x_pos, 15, 90, 20, fillColor=box_color, strokeColor=colors.black))
            # Add checkmark or X
            symbol = '✓' if source_active else '✗'
            symbol_color = colors.green if source_active else colors.red
            source_drawing.add(String(x_pos + 45, 23, symbol, fontSize=14, fillColor=symbol_color, textAnchor='middle', fontName='Helvetica-Bold'))
            # Add label
            source_drawing.add(String(x_pos + 45, 5, api[:10], fontSize=7, fillColor=colors.black, textAnchor='middle'))
            x_pos += 100

        # Add coverage summary
        coverage_text = f"{len(sources)}/4 sources"
        coverage_color = colors.green if len(sources) == 4 else colors.orange if len(sources) >= 3 else colors.red
        source_drawing.add(String(200, 40, coverage_text, fontSize=10, fillColor=coverage_color, textAnchor='middle', fontName='Helvetica-Bold'))

        elements.append(source_drawing)
        elements.append(Spacer(1, 0.2*inch))

        # MITRE ATT&CK Section
        mitre_attack = data_dict.get('mitre_attack', [])
        if mitre_attack:
            elements.append(
                Paragraph("MITRE ATT&CK TECHNIQUES", heading_style))

            mitre_data = [['Technique ID', 'Name', 'Tactic']]
            for technique in mitre_attack[:10]:  # Limit to top 10
                mitre_data.append([
                    technique.get('id', 'N/A'),
                    technique.get('name', 'N/A'),
                    technique.get('tactic', 'N/A')
                ])

            if len(mitre_attack) > 10:
                mitre_data.append(
                    ['...', f'+ {len(mitre_attack) - 10} more techniques', ''])

            mitre_table = Table(mitre_data, colWidths=[
                                1.5*inch, 2.5*inch, 2*inch])
            mitre_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffebee')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d32f2f'))
            ]))
            elements.append(mitre_table)
            elements.append(Paragraph(
                f"<i>Total: {len(mitre_attack)} technique(s) mapped | Reference: attack.mitre.org</i>",
                ParagraphStyle(
                    'MitreNote', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
            ))
            elements.append(Spacer(1, 0.2*inch))

        # Kill Chain Section
        kill_chain_stages = data_dict.get('kill_chain_stages', [])
        elements.append(Paragraph("CYBER KILL CHAIN ANALYSIS", heading_style))

        # Kill Chain Progress Visual
        kc_drawing = Drawing(400, 60)
        stages_detected = len(kill_chain_stages)
        total_stages = 7

        # Progress bar background
        kc_drawing.add(Rect(0, 30, 300, 20, fillColor=colors.lightgrey, strokeColor=colors.black))

        # Progress bar fill (orange gradient)
        progress_width = (stages_detected / total_stages) * 300
        kc_bar_color = colors.HexColor('#ff6600') if stages_detected > 0 else colors.lightgrey
        kc_drawing.add(Rect(0, 30, progress_width, 20, fillColor=kc_bar_color, strokeColor=None))

        # Label
        kc_label = f"{stages_detected}/{total_stages} Stages Detected"
        label_color = colors.HexColor('#ff6600') if stages_detected > 0 else colors.grey
        kc_drawing.add(String(150, 10, kc_label,
                              fontSize=12, fillColor=label_color, textAnchor='middle', fontName='Helvetica-Bold'))

        elements.append(kc_drawing)
        elements.append(Spacer(1, 0.15*inch))

        all_stages = [
            '1. Reconnaissance',
            '2. Weaponization',
            '3. Delivery',
            '4. Exploitation',
            '5. Installation',
            '6. Command & Control',
            '7. Actions on Objectives'
        ]

        kc_data = [['Stage', 'Status']]
        for stage in all_stages:
            status = '● IDENTIFIED' if stage in kill_chain_stages else '○ Not Detected'
            kc_data.append([stage, status])

        kc_table = Table(kc_data, colWidths=[3*inch, 3*inch])

        # Build row styles dynamically
        kc_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ff6f00')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ff6f00'))
        ]

        # Highlight identified stages
        for i, stage in enumerate(all_stages, start=1):
            if stage in kill_chain_stages:
                kc_style.append(('BACKGROUND', (0, i), (-1, i),
                                colors.HexColor('#fff3e0')))
                kc_style.append(('TEXTCOLOR', (1, i), (1, i),
                                colors.HexColor('#e65100')))
                kc_style.append(('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'))
            else:
                kc_style.append(('BACKGROUND', (0, i), (-1, i),
                                colors.HexColor('#fafafa')))
                kc_style.append(('TEXTCOLOR', (1, i), (1, i), colors.grey))

        kc_table.setStyle(TableStyle(kc_style))
        elements.append(kc_table)

        if kill_chain_stages:
            progression = f"Attack spans {len(kill_chain_stages)} stage(s): {', '.join(kill_chain_stages)}"
        else:
            progression = "No Kill Chain stages identified for this indicator."
        elements.append(Paragraph(
            f"<i>{progression} | Reference: Lockheed Martin Cyber Kill Chain</i>",
            ParagraphStyle(
                'KCNote', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
        ))
        elements.append(Spacer(1, 0.2*inch))

        # Network Profile Section
        usage_type = data_dict.get('usage_type')
        asn = data_dict.get('asn')
        asn_name = data_dict.get('asn_name')
        num_distinct_reporters = data_dict.get('num_distinct_reporters', 0)

        if usage_type or asn or num_distinct_reporters > 0:
            elements.append(Paragraph("NETWORK PROFILE", heading_style))

            network_data = [['Field', 'Value']]
            if usage_type:
                network_data.append(['Usage Type', usage_type])
            if asn:
                asn_display = f"{asn} - {asn_name}" if asn_name else asn
                network_data.append(['Autonomous System', asn_display])
            if num_distinct_reporters > 0:
                network_data.append(['Unique Reporters', str(num_distinct_reporters)])

            network_table = Table(network_data, colWidths=[2*inch, 4*inch])
            network_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00bcd4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(network_table)
            elements.append(Spacer(1, 0.2*inch))

        # Temporal Intelligence Section
        first_seen = data_dict.get('first_seen')
        last_seen = data_dict.get('last_seen')

        if first_seen or last_seen:
            elements.append(Paragraph("TEMPORAL INTELLIGENCE", heading_style))

            temporal_data = [['Observation', 'Timestamp']]
            if first_seen:
                temporal_data.append(['First Observed', first_seen])
            if last_seen:
                temporal_data.append(['Last Observed', last_seen])

            temporal_table = Table(temporal_data, colWidths=[2*inch, 4*inch])
            temporal_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00bcd4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(temporal_table)
            elements.append(Spacer(1, 0.2*inch))

        # Malware & Attribution Section
        malware_families = data_dict.get('malware_families', [])
        threat_actor = data_dict.get('threat_actor')

        if malware_families or threat_actor:
            elements.append(Paragraph("MALWARE & ATTRIBUTION", heading_style))

            attribution_data = [['Field', 'Value']]
            if malware_families and len(malware_families) > 0:
                malware_list = ', '.join(malware_families)
                attribution_data.append(['Malware Families', malware_list])
            if threat_actor:
                attribution_data.append(['Threat Actor', threat_actor])

            attribution_table = Table(attribution_data, colWidths=[2*inch, 4*inch])
            attribution_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f44336')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffebee')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(attribution_table)
            elements.append(Spacer(1, 0.2*inch))

        # Privacy Services Detection Section
        is_tor = data_dict.get('is_tor', False)
        is_vpn = data_dict.get('is_vpn', False)
        is_proxy = data_dict.get('is_proxy', False)
        is_bot = data_dict.get('is_bot', False)

        if is_tor or is_vpn or is_proxy or is_bot:
            elements.append(Paragraph("PRIVACY & ANONYMIZATION SERVICES", heading_style))

            privacy_data = [['Service', 'Status']]
            if is_tor:
                privacy_data.append(['TOR Exit Node', 'DETECTED'])
            if is_vpn:
                privacy_data.append(['VPN Service', 'DETECTED'])
            if is_proxy:
                privacy_data.append(['Proxy Service', 'DETECTED'])
            if is_bot:
                privacy_data.append(['Bot Activity', 'DETECTED'])

            privacy_table = Table(privacy_data, colWidths=[3*inch, 3*inch])
            privacy_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ff9800')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fff3e0')),
                ('TEXTCOLOR', (1, 1), (1, -1), colors.HexColor('#e65100')),
                ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(privacy_table)
            elements.append(Spacer(1, 0.2*inch))

        # Community Intelligence Section
        community_votes = data_dict.get('community_votes', {})
        tags = data_dict.get('tags', [])

        if (community_votes and (community_votes.get('harmless', 0) > 0 or community_votes.get('malicious', 0) > 0)) or (tags and len(tags) > 0):
            elements.append(Paragraph("COMMUNITY INTELLIGENCE", heading_style))

            community_data = [['Source', 'Information']]

            if community_votes and (community_votes.get('harmless', 0) > 0 or community_votes.get('malicious', 0) > 0):
                harmless = community_votes.get('harmless', 0)
                malicious = community_votes.get('malicious', 0)
                total_votes = harmless + malicious
                votes_summary = f"Harmless: {harmless} | Malicious: {malicious} | Total: {total_votes}"
                community_data.append(['VirusTotal Votes', votes_summary])

            if tags and len(tags) > 0:
                tags_display = ', '.join(tags[:10])  # Limit to 10 tags for PDF
                if len(tags) > 10:
                    tags_display += f' (+{len(tags) - 10} more)'
                community_data.append(['Community Tags', tags_display])

            community_table = Table(community_data, colWidths=[2*inch, 4*inch])
            community_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00bcd4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(community_table)
            elements.append(Spacer(1, 0.2*inch))

        # Recommendation Section
        recommendation = data_dict.get('recommendation', {})
        if recommendation:
            elements.append(Paragraph("RECOMMENDATION", heading_style))

            # Create a style for wrapped text in table cells
            cell_style = ParagraphStyle(
                'CellText',
                parent=styles['Normal'],
                fontSize=10,
                leading=12
            )

            rec_data = [
                ['Action', recommendation.get('action', 'N/A')],
                ['Priority', recommendation.get('priority', 'N/A')],
                ['Justification', Paragraph(recommendation.get(
                    'justification', 'N/A'), cell_style)],
            ]

            # Add confidence note if present
            if recommendation.get('confidence_note'):
                rec_data.append(
                    ['Confidence Note', Paragraph(recommendation.get('confidence_note'), cell_style)])

            rec_table = Table(rec_data, colWidths=[1.8*inch, 4.2*inch])
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
