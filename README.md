<div align="center">

## [🎯 FEATURED AT BLACKHAT ARSENAL 2025 🎯](https://www.blackhat.com/sector/2025/arsenal/schedule/index.html#farsight-cli-based-recon-and-threat-intelligence-framework-47707)

**Join us at BlackHat Arsenal 2025** | **Session: CLI-Based Recon and Threat Intelligence Framework**

</div>

<p align="center">
  <img src="docs/assets/logo.svg" alt="FARSIGHT Logo" width="100%"/>
</p>

# FARSIGHT

[![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/seedon198/Farsight?style=for-the-badge)](https://github.com/seedon198/Farsight/stargazers)

*A comprehensive reconnaissance and threat intelligence framework trusted by security professionals worldwide*

## Overview

FARSIGHT is a powerful, Python-based reconnaissance and threat intelligence framework designed for security professionals. It provides comprehensive domain intelligence, asset discovery, and threat monitoring capabilities in a fast, modular CLI-first tool.

### Key Features

- **Pure Python Implementation**: Entirely built in Python for maximum portability
- **API-Optional Architecture**: Functions with or without API keys, with enhanced fallback mechanisms
- **Fast & Modular**: Async-first design for optimal performance with parallel processing
- **CLI-First Approach**: Intuitive command-line interface using Typer
- **Comprehensive Reporting**: Generates detailed Markdown and PDF reports with visual risk indicators
- **Graceful Degradation**: Recovers smoothly from API failures with smart alternative methods
- **No External Binary Dependencies**: Optional integration with external tools

## Modules

1. **Organizational Domain Discovery**: WHOIS analysis, certificate transparency data, passive DNS, related domain discovery
2. **Recon / Asset Discovery**: Advanced DNS enumeration, comprehensive port scanning on all discovered subdomains
3. **Threat Intelligence**: Leak detection, credential exposure, dark web mentions, email reputation analysis
4. **Typosquatting Detection**: Optimized domain permutation and analysis with content similarity assessment
5. **News Monitoring**: Comprehensive news tracking with multiple source support and relevance scoring
6. **Report Generation**: Structured output in Markdown/PDF formats with visual risk indicators

## Installation

FARSIGHT requires Python 3.9+ and several dependencies. Follow these steps for a complete setup:

### Prerequisites

- Python 3.9 or higher
- pip (Python package installer)

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/seedon198/Farsight.git
cd Farsight

# 2. Create a virtual environment (recommended)
python3 -m venv venv

# 3. Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# 4. Install core dependencies
pip install -r requirements.txt

# 5. Install optional dependencies for full functionality
pip install dnstwist rapidfuzz gnews markdown reportlab

# 6. Verify installation
python -m farsight --help
```

### Quick Start

Once installed, you can immediately start using FARSIGHT:

```bash
# Activate your virtual environment
source venv/bin/activate

# Run a basic scan
python -m farsight scan example.com

# Run a comprehensive scan with all modules
python -m farsight scan example.com --all --verbose
```

### Alternative: Using Poetry (Recommended for Development)

If you prefer using Poetry for dependency management:

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell

# Run FARSIGHT
poetry run python -m farsight --help
```

### Development Setup

For development and contributing:

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks (optional)
pre-commit install
```

### API Keys (Optional)

FARSIGHT can function without API keys, but some features will be limited. For the best experience, consider setting up the following API keys as environment variables:

```bash
export FARSIGHT_SHODAN_API_KEY="your-api-key"
export FARSIGHT_CENSYS_API_KEY="your-api-key"
export FARSIGHT_SECURITYTRAILS_API_KEY="your-api-key"
export FARSIGHT_VIRUSTOTAL_API_KEY="your-api-key"
export FARSIGHT_INTELX_API_KEY="your-api-key"
export FARSIGHT_LEAKPEEK_API_KEY="your-api-key"
```

## Usage

FARSIGHT is designed to be simple to use while providing powerful reconnaissance capabilities. Make sure to activate your virtual environment first:

```bash
# Activate virtual environment (if using one)
source venv/bin/activate  # On macOS/Linux
# or
# venv\Scripts\activate  # On Windows
```

### Basic Commands

```bash
# Display help information
python -m farsight --help

# Display version information
python -m farsight version

# Show scan command options
python -m farsight scan --help
```

### Running Scans

```bash
# Basic scan (organization discovery + reconnaissance)
python -m farsight scan example.com

# Basic scan with custom output file
python -m farsight scan example.com --output my_report.md

# Comprehensive scan with all modules
python -m farsight scan example.com --all --verbose

# Custom scan with specific modules
python -m farsight scan example.com --modules org,recon,threat --verbose

# Generate a PDF report
python -m farsight scan example.com --output report.pdf --all

# Force overwrite existing report
python -m farsight scan example.com --force
```

### Scan Depth Levels

FARSIGHT supports different scan depth levels that control how thorough the scanning process is:

- **Depth 1**: Basic reconnaissance (default) - Fast, non-intrusive scanning
- **Depth 2**: Enhanced reconnaissance - More thorough scanning with additional checks
- **Depth 3**: Comprehensive analysis - Most thorough scanning with all available techniques

```bash
# Run a quick scan (depth 1)
python -m farsight scan example.com --depth 1

# Run a thorough scan (depth 3)
python -m farsight scan example.com --depth 3 --all
```

## Modules

FARSIGHT is designed with a modular architecture, allowing you to use specific modules independently or together. Here's an overview of each module:

### Organization Discovery

This module discovers domains related to an organization through various techniques:

- WHOIS data analysis for organization information
- Certificate Transparency logs from crt.sh
- Passive DNS data from public sources
- Optional API-based lookups (SecurityTrails, Censys)

### Reconnaissance

This module identifies assets and network infrastructure:

- DNS enumeration (A, AAAA, MX, TXT, NS records)
- Advanced subdomain discovery using multiple techniques:
  - Certificate Transparency logs
  - DNS brute forcing
  - Passive DNS sources
- Comprehensive port scanning on all discovered subdomains using asyncio
- Email security assessment (SPF, DMARC, DKIM)
- Optional API-based services (Shodan, Censys)

### Threat Intelligence

This module identifies potential security threats:

- Data leak detection from public sources
- Credential exposure monitoring with breach correlation
- Advanced dark web mentions tracking with risk categorization
- Email reputation analysis with risk scoring
- Alternative monitoring methods when APIs are unavailable
- Visual risk indicators in reports (🟢, 🔵, 🔴, ⚠️)

### Typosquatting Detection

This module identifies potential typosquatting domains:

- Optimized domain permutation generation
- Enhanced DNS resolution checks with fallback mechanisms
- Registration data analysis with age assessment
- Advanced content similarity checks
- MX record analysis for phishing detection
- Improved similarity threshold (60% default) for better detection
- Analyzes similarity and risk scoring
- Detects domain squatting techniques

### News Monitoring

This module tracks recent news mentions:

- Recent news articles about the target with multiple source support
- Source credibility assessment and publisher information
- Relevance scoring for each article
- Alternative methods when primary API is unavailable
- Clean output formatting with prioritized articles

### Report Generation

This module generates comprehensive reports:

- Markdown reports with detailed findings
- Optional PDF conversion
- Structured data presentation
- Executive summaries and technical details

## Configuration

FARSIGHT's behavior can be configured through environment variables or direct parameters:

### Environment Variables

Set these environment variables to configure API keys and global settings:

```bash
# API Keys
export FARSIGHT_SHODAN_API_KEY="your-api-key"
export FARSIGHT_CENSYS_API_KEY="your-api-key"
export FARSIGHT_SECURITYTRAILS_API_KEY="your-api-key"
export FARSIGHT_VIRUSTOTAL_API_KEY="your-api-key"
export FARSIGHT_INTELX_API_KEY="your-api-key"
export FARSIGHT_LEAKPEEK_API_KEY="your-api-key"

# Global Settings
export FARSIGHT_TIMEOUT=60  # Default timeout in seconds
export FARSIGHT_MAX_CONCURRENT=20  # Max concurrent requests
```

### Command Line Options

Many configuration options can be provided directly on the command line:

```bash
# Set timeout and concurrency
python -m farsight scan example.com --timeout 60 --concurrency 20

# Force overwrite existing reports
python -m farsight scan example.com --output report.md --force

# Enable verbose output for debugging
python -m farsight scan example.com --verbose
```

## Reporting

FARSIGHT generates comprehensive reports in Markdown format by default, with optional PDF conversion if the required libraries are installed. Reports include:

- Executive summary with key findings
- Detailed technical results from each module
- Visual representations of data where applicable
- Recommendations based on findings

Example report sections:

```markdown
# FARSIGHT Reconnaissance Report
            
## Target: example.com
**Scan Date:** 2025-05-17 17:57:11
**Scan Depth:** 2
**Modules Run:** org, recon, threat, typosquat, news

## Executive Summary

This report presents the findings from a reconnaissance scan of **example.com**.

- **12** domains/subdomains discovered
- **5** open ports found
- **Well-protected** email security posture
```

## Project Architecture

FARSIGHT is built with the following architecture:

```
farsight/
├── __init__.py           # Package initialization
├── __main__.py           # CLI entry point
├── main.py               # Main CLI application
├── config.py             # Configuration management
├── cli/                  # CLI interface using Typer
│   └── scan.py           # Scan command implementation
├── modules/              # Core functionality modules
│   ├── org_discovery.py  # Organization domain discovery
│   ├── recon.py          # DNS enumeration and port scanning
│   ├── threat_intel.py   # Threat intelligence gathering
│   ├── typosquat.py      # Typosquatting detection
│   ├── news.py           # News monitoring
│   └── report_writer.py  # Report generation
└── utils/                # Utility functions
    ├── api_handler.py    # API interaction with failover
    ├── common.py         # Common utilities
    ├── dns.py            # DNS operations
    └── subdomain_enum.py # Subdomain enumeration utilities
```

## Dependencies

### Core Dependencies (Required)
- **typer**: CLI interface framework
- **python-whois**: WHOIS lookups
- **aiohttp**: Asynchronous HTTP requests
- **dnspython**: DNS resolution and querying
- **beautifulsoup4**: Web scraping
- **requests**: HTTP library for API requests

### Optional Dependencies (Recommended)
- **dnstwist**: Enhanced typosquatting detection
- **rapidfuzz**: Better similarity scoring for typosquatting
- **gnews**: News article retrieval
- **markdown**: Markdown report processing
- **reportlab**: PDF report generation

### Installation Notes

- All core dependencies are installed with `pip install -r requirements.txt`
- Optional dependencies can be installed with: `pip install dnstwist rapidfuzz gnews markdown reportlab`
- The tool will work without optional dependencies but with limited functionality

## Troubleshooting

### Common Issues

**Issue: `No module named farsight.__main__`**
```bash
# Solution: Make sure you're in the project directory and using the correct Python
cd /path/to/Farsight
python -m farsight --help
```

**Issue: `ModuleNotFoundError` for optional dependencies**
```bash
# Solution: Install optional dependencies
pip install dnstwist rapidfuzz gnews markdown reportlab
```

**Issue: Permission denied when creating virtual environment**
```bash
# Solution: Use --user flag or check permissions
python3 -m venv --user venv
# or
sudo python3 -m venv venv
```

**Issue: Command not found: python**
```bash
# Solution: Use python3 instead
python3 -m farsight --help
```

**Issue: Report file already exists**
```bash
# Solution: Use --force flag to overwrite
python -m farsight scan example.com --force
```

### Getting Help

1. Check the help: `python -m farsight --help`
2. Check scan options: `python -m farsight scan --help`
3. Run with verbose output: `python -m farsight scan example.com --verbose`
4. Check the [GitHub Issues](https://github.com/seedon198/Farsight/issues) for known problems

## Contributing

FARSIGHT is an open-source project and welcomes contributions. Here's how you can contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

FARSIGHT is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

FARSIGHT leverages the following projects and services:

- [Typer](https://typer.tiangolo.com/) - CLI framework
- [aiohttp](https://docs.aiohttp.org/) - Asynchronous HTTP client/server
- [dnspython](https://www.dnspython.org/) - DNS toolkit
- [python-whois](https://pypi.org/project/python-whois/) - WHOIS lookup
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - Web scraping
- [dnstwist](https://github.com/elceef/dnstwist) - Domain permutation engine
- [rapidfuzz](https://github.com/maxbachmann/rapidfuzz) - Fast string matching
- [gnews](https://github.com/ranahaani/gnews) - News article retrieval
- [markdown](https://python-markdown.github.io/) - Markdown parsing
- [reportlab](https://www.reportlab.com/) - PDF generation
- Public data sources including [crt.sh](https://crt.sh/), [RapidDNS](https://rapiddns.io/), and [DNSDB.io](https://dnsdb.io/)

## Disclaimer

FARSIGHT is provided as-is, without warranty of any kind, express or implied. The authors and contributors disclaim all liability for any damages arising from its use.

This tool is designed for security professionals conducting authorized security assessments. Always ensure you have proper authorization before scanning any domain or network.

## Contact

For questions, suggestions, or support, please open an issue on the [GitHub repository](https://github.com/seedon198/Farsight).
