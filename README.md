<p align="center">
  <img src="docs/assets/logo.svg" alt="FARSIGHT Logo"/>
</p>

## Overview

FARSIGHT is a powerful, Python-based reconnaissance and threat intelligence framework designed for security professionals. It provides comprehensive domain intelligence, asset discovery, and threat monitoring capabilities in a fast, modular CLI-first tool.

### Key Features

- **Pure Python Implementation**: Entirely built in Python for maximum portability
- **API-Optional Architecture**: Functions with or without API keys
- **Fast & Modular**: Async-first design for optimal performance
- **CLI-First Approach**: Intuitive command-line interface using Typer
- **Comprehensive Reporting**: Generates detailed Markdown and PDF reports
- **Graceful Degradation**: Recovers smoothly from API failures
- **No External Binary Dependencies**: Optional integration with tools like masscan

## Modules

1. **Organizational Domain Discovery**: WHOIS analysis, certificate transparency data, passive DNS
2. **Recon / Asset Discovery**: DNS enumeration, port scanning, service detection
3. **Threat Intelligence**: Leak detection, credential exposure, dark web mentions
4. **Typosquatting Detection**: Domain permutation generation and analysis
5. **News Monitoring**: Track latest news mentions of target organizations
6. **Report Generation**: Structured output in Markdown/PDF formats

## Installation

```bash
# Install using pip
pip install farsight

# Or install using Poetry
poetry add farsight
```

## Usage

```bash
# Run farsight with help
farsight --help

# Run a basic scan
farsight scan example.com --output report.md

# Run a comprehensive scan with all modules
farsight scan example.com --output report.md --depth 2 --news --typosquat --threat-intel
```

## Configuration

FARSIGHT supports various configuration options through environment variables, config files, or command-line arguments.

```bash
# Set API keys via environment variables
export FARSIGHT_SHODAN_API_KEY="your-api-key"
export FARSIGHT_CENSYS_API_KEY="your-api-key"

# Set API keys via config file
farsight config set shodan_api_key "your-api-key"
farsight config set censys_api_key "your-api-key"

# Set API keys via command-line arguments
farsight scan example.com --shodan-api-key "your-api-key" --censys-api-key "your-api-key"
```

## Output

FARSIGHT can generate reports in Markdown and PDF formats.

```bash
# Generate Markdown report
farsight scan example.com --output report.md

# Generate PDF report
farsight scan example.com --output report.pdf
```

## Depth

FARSIGHT can perform a scan at different depths, with each depth representing a different level of detail and complexity.

```bash
# Run a basic scan
farsight scan example.com --output report.md --depth 1

# Run a comprehensive scan with all modules
farsight scan example.com --output report.md --depth 2 --news --typosquat --threat-intel
```

## News

FARSIGHT can track news mentions of target organizations.

```bash
# Track news mentions of target organizations
farsight news example.com
```

## Typosquat

FARSIGHT can detect typosquatting attempts.

```bash
# Detect typosquatting attempts
farsight typosquat example.com
```

## Threat Intel

FARSIGHT can detect potential threats to target organizations.

```bash
# Detect potential threats to target organizations
farsight threat-intel example.com
```

## Typosquat

FARSIGHT can detect typosquatting attempts.

```bash
# Detect typosquatting attempts
farsight typosquat example.com
```

## Contributing

FARSIGHT is an open-source project, and we welcome contributions from the community. Please see our [CONTRIBUTING.md](CONTRIBUTING.md) file for more information on how to contribute to the project.

## License

FARSIGHT is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Acknowledgments

FARSIGHT is built on top of the following open-source projects and other services:

- [Typer](https://typer.tiangolo.com/)
- [Requests](https://requests.readthedocs.io/)
- [PyPDF2](https://pypdf2.readthedocs.io/)
- [Markdown](https://markdown.readthedocs.io/)
- [Shodan](https://shodan.io/)
- [Censys](https://censys.io/)
- [Masscan](https://github.com/robertdavidgraham/masscan)
- [WHOIS](https://whois.com/)
- [Certificate Transparency](https://crt.sh/)
- [Passive DNS](https://viewdns.info/)

## Disclaimer

FARSIGHT is provided as-is, without warranty of any kind, express or implied. The authors and contributors disclaim all liability for any damages arising from the use of FARSIGHT.

## Support

FARSIGHT is a community-driven project, and we welcome contributions from the community. Please see our [CONTRIBUTING.md](CONTRIBUTING.md) file for more information on how to contribute to the project.

## Contact

For support, please open an issue on the [GitHub repository](https://github.com/seedon198/farsight).
