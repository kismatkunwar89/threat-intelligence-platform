# Threat Intelligence Platform

A full-stack web application that aggregates threat intelligence data from multiple authoritative sources to provide comprehensive IP address reputation analysis and security assessment.

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

This application provides security analysts with unified threat intelligence by aggregating data from four leading threat intelligence sources. It normalizes disparate API responses, enriches data with MITRE ATT&CK mappings and Cyber Kill Chain analysis, and delivers actionable recommendations through a professional dark-themed interface.

## Features

### Core Functionality
- **Multi-Source Intelligence Aggregation**: Combines data from AbuseIPDB, AlienVault OTX, VirusTotal, and GreyNoise
- **IPv4/IPv6 Support**: Comprehensive validation for all IP address formats
- **Smart Caching**: MySQL-based caching with 24-hour TTL (40-60% cache hit rate)
- **Risk Scoring**: Weighted risk calculation (0-100 scale) across multiple sources
- **MITRE ATT&CK Mapping**: Automatic tactic and technique identification
- **Cyber Kill Chain Analysis**: 7-stage attack progression visualization

### Enhanced Intelligence
- **Network Profiling**: ASN, ISP, usage type, geographic location
- **Temporal Analysis**: First seen, last seen timestamps
- **Malware Attribution**: Associated malware families and threat actors
- **Privacy Detection**: VPN, Tor, proxy, and bot identification
- **Community Intelligence**: VirusTotal votes, tags, and community feedback

### Export Capabilities
- **JSON Export**: API-ready structured data
- **CSV Export**: Spreadsheet-compatible format
- **PDF Reports**: Professional reports with visual risk indicators

### User Interface
- **Dark Cybersecurity Theme**: Professional Semantic UI-based interface
- **Visual Risk Indicators**: SVG gauges, progress bars, color-coded risk levels
- **Real-Time Progress**: 10-step loading modal with status updates
- **Responsive Design**: Mobile and desktop compatible

## Technology Stack

**Backend:**
- Python 3.13
- Flask 3.1.0 (Web framework)
- MySQL + PyMySQL (Database and driver)
- ReportLab 4.2.5 (PDF generation)

**Frontend:**
- Semantic UI 2.5.0 (CSS framework)
- Custom CSS (Dark theme)
- Vanilla JavaScript (Interactions)
- Jinja2 (Template engine)

**External APIs:**
- AbuseIPDB (Abuse reports & reputation)
- AlienVault OTX (Community threat intelligence)
- VirusTotal (Malware analysis)
- GreyNoise (Internet scanning intelligence)

## Architecture

### Design Patterns
The application implements 8 industry-standard design patterns:

1. **Factory Pattern**: `create_app()` for flexible application configuration
2. **Blueprint Pattern**: Modular routing for threat intelligence
3. **Client Pattern**: Encapsulated API communication (4 clients)
4. **Normalizer Pattern**: Data transformation to canonical schema
5. **DTO Pattern**: `ThreatIntelResult` dataclass (30+ fields)
6. **Strategy Pattern**: Recommendation engine based on risk scores
7. **Singleton Pattern**: Single cache instance across requests
8. **Template Inheritance**: Base template with blocks for reusability

### Project Structure

```
threat-intelligence-platform/
├── app.py                      # Flask application factory
├── config.py                   # Environment-based configuration
├── requirements.txt            # Python dependencies
│
├── models/
│   ├── database.py            # Database connection management
│   ├── cache.py               # CRUD operations for caching
│   ├── threat_intel_result.py # Canonical data structure (30+ fields)
│   ├── schema.sql             # MySQL schema
│   └── init_db.py             # Database initialization
│
├── routes/
│   └── threat_intel.py        # Flask routes (Blueprint pattern)
│
├── services/
│   ├── threat_intel_client.py # Base API client (ABC pattern)
│   ├── abuseipdb_client.py    # AbuseIPDB integration
│   ├── otx_client.py          # AlienVault OTX integration
│   ├── virustotal_client.py   # VirusTotal integration
│   └── greynoise_client.py    # GreyNoise integration
│
├── utils/
│   ├── ip_validator.py        # IP validation with ipaddress module
│   ├── normalizer.py          # Data normalization from 4 APIs
│   ├── mitre_mapper.py        # MITRE ATT&CK mapping
│   ├── kill_chain_mapper.py   # Cyber Kill Chain analysis
│   ├── recommendation_engine.py # Risk-based recommendations
│   └── logger.py              # Logging configuration
│
├── templates/
│   ├── threat_intel/
│   │   ├── base.html          # Base template (inheritance pattern)
│   │   ├── index.html         # IP lookup form
│   │   ├── results.html       # Threat intel results display
│   │   └── about.html         # About page
│   └── errors/
│       ├── 404.html           # Not found page
│       └── 500.html           # Server error page
│
├── static/
│   └── css/
│       ├── threat_intel.css   # Dark theme styling
│       └── semantic_overrides.css # Semantic UI customizations
│
├── tests/
│   ├── test_components.py     # Component integration tests
│   ├── test_normalizer.py     # Normalization tests
│   └── quick_test.py          # Manual testing script
│
└── scripts/
    └── download_mitre_data.py # MITRE ATT&CK data download
```

## Installation

### Prerequisites

- Python 3.8+
- MySQL Server 5.7+
- API Keys (free tiers available):
  - [AbuseIPDB](https://www.abuseipdb.com/api) - 1,000 requests/day
  - [AlienVault OTX](https://otx.alienvault.com/) - Unlimited
  - [VirusTotal](https://www.virustotal.com/gui/join-us) - 500 requests/day
  - [GreyNoise](https://www.greynoise.io/plans/community) - 25 requests/week

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/kismatkunwar89/threat-intelligence-platform.git
   cd threat-intelligence-platform
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:

   Create `.env` file in project root:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=your_username
   DB_PASSWORD=your_password
   DB_NAME=threat_intel_db

   # API Keys
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   OTX_API_KEY=your_otx_key
   VIRUSTOTAL_API_KEY=your_virustotal_key
   GREYNOISE_API_KEY=your_greynoise_key

   # Application Settings
   FLASK_ENV=development
   SECRET_KEY=your-secret-key-here
   CACHE_TTL_SECONDS=86400
   API_TIMEOUT_SECONDS=10
   ```

5. **Initialize database**:
   ```bash
   python3 models/init_db.py
   ```

6. **Download MITRE ATT&CK data**:
   ```bash
   python3 scripts/download_mitre_data.py
   ```

## Usage

### Running the Application

**Development:**
```bash
source venv/bin/activate
python3 app.py
```

**Production:**
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Access the application:
- Local: http://127.0.0.1:5000
- Network: http://<your-ip>:5000

### Using the Interface

1. Navigate to the home page
2. Enter an IPv4 or IPv6 address
3. Click "ANALYZE THREAT INTELLIGENCE"
4. View comprehensive results with:
   - Risk score and confidence level
   - Data from multiple sources
   - Enhanced intelligence cards
   - MITRE ATT&CK tactics
   - Cyber Kill Chain stages
   - Actionable recommendations
5. Export results as JSON, CSV, or PDF

## API Data Sources

### AbuseIPDB
- Abuse confidence score (0-100)
- Total reports and distinct reporters
- Country, ISP, usage type
- Last reported timestamp

### AlienVault OTX
- Pulse count (community reports)
- Malware families
- Associated tags
- Threat actor attribution

### VirusTotal
- Malicious/suspicious votes
- Harmless votes
- Community tags
- Last analysis statistics

### GreyNoise
- Classification (benign/malicious/unknown)
- First seen / Last seen timestamps
- VPN, Tor, proxy detection
- Bot classification

## Security Features

1. **Input Validation**: Python `ipaddress` module for strict IP validation
2. **SQL Injection Prevention**: Parameterized queries exclusively
3. **XSS Prevention**: Jinja2 auto-escaping enabled
4. **API Key Security**: Environment variables via python-dotenv
5. **Error Handling**: Custom error pages without stack trace exposure
6. **Rate Limiting Protection**: Caching reduces API calls by 40-60%

## Performance

- **Cached Lookups**: < 50ms response time
- **Fresh API Lookups**: 3-5 seconds
- **Cache Hit Rate**: 40-60% in typical usage
- **Database Queries**: < 10ms average
- **PDF Generation**: 1-2 seconds

## Testing

```bash
# Run component tests
python3 tests/test_components.py

# Run normalization tests
python3 tests/test_normalizer.py

# Quick integration test
python3 tests/quick_test.py
```

## Contributing

Contributions are welcome! Please follow these guidelines:

- Follow PEP 8 style guide
- Use type hints for all functions
- Write comprehensive docstrings
- Add tests for new functionality
- Keep commits atomic and well-described

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **AbuseIPDB** - IP abuse reporting service
- **AlienVault OTX** - Open Threat Exchange community
- **VirusTotal** - Malware analysis platform
- **GreyNoise** - Internet scanning intelligence
- **MITRE** - ATT&CK framework
- **Flask** - Web application framework
- **Semantic UI** - CSS framework

## Project Status

✅ **Production Ready**
- 4 API integrations fully functional
- Comprehensive error handling
- Professional UI with dark theme
- Export capabilities (JSON, CSV, PDF)
- Caching system operational
- Security measures implemented

## Roadmap

**Completed:**
- ✅ Multi-source API integration
- ✅ Data normalization and aggregation
- ✅ MITRE ATT&CK mapping
- ✅ Cyber Kill Chain analysis
- ✅ MySQL caching with TTL
- ✅ Semantic UI integration
- ✅ PDF report generation
- ✅ Enhanced intelligence fields

**Future Enhancements:**
- Domain and hash lookups
- Historical trend analysis
- Advanced filtering and search
- User authentication system
- RESTful API endpoints
- Real-time monitoring dashboard

---

**Developed by Kismat** | [GitHub Repository](https://github.com/kismatkunwar89/threat-intelligence-platform)
