"""Report generation module for FARSIGHT."""

import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import re
import os

from farsight.utils.common import logger
from farsight.config import get_config, REPORTS_DIR

# Try to import markdown to PDF converters
PDF_SUPPORT = False
try:
    import markdown
    import weasyprint
    PDF_SUPPORT = True
except ImportError:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        import markdown
        PDF_SUPPORT = True
    except ImportError:
        logger.warning("PDF conversion libraries not installed. Only Markdown reports will be generated.")


class ReportWriter:
    """Report generation class for creating Markdown and PDF reports."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize report writer.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir or REPORTS_DIR
        # Ensure directory exists
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Templates as multi-line strings
        self.templates = {
            "header": """# FARSIGHT Reconnaissance Report
            
## Target: {target}
**Scan Date:** {date}
**Scan Depth:** {depth}
**Modules Run:** {modules}

---
""",
            "summary": """## Executive Summary

This report presents the findings from a reconnaissance scan of **{target}**.

- **{total_domains}** domains/subdomains discovered
- **{total_open_ports}** open ports found
- **{email_security_status}** email security posture
{additional_summary_points}

---
""",
            "org_discovery": """## Organization & Domain Discovery

### WHOIS Information
{whois_info}

### Discovered Domains ({total_domains})
{domains_list}

### Certificate Transparency Data
{certificate_transparency}

---
""",
            "recon": """## Reconnaissance & Asset Discovery

### DNS Records
{dns_records}

### Subdomains Discovered
{subdomains}

### Port Scan Results
{port_scan}

### Email Security Assessment
{email_security}

---
""",
            "threat_intel": """## Threat Intelligence

### Data Leaks & Breaches
{leaks}

### Dark Web Mentions
{dark_web}

### Exposed Credentials
{credentials}

---
""",
            "typosquat": """## Typosquatting Analysis

### Detected Typosquats ({total_typosquats})
{typosquats}

---
""",
            "news": """## News Monitoring

### Recent News Articles
{news_articles}

---
""",
            "footer": """## About This Report

This report was generated automatically by FARSIGHT v{version} on {date}.

All data in this report is presented for informational purposes only.
"""
        }
    
    def generate_report(self, 
                       results: Dict[str, Dict[str, Any]], 
                       target: str, 
                       depth: int, 
                       modules: List[str], 
                       output_file: Optional[Union[str, Path]] = None) -> Path:
        """
        Generate a comprehensive report from all module results.
        
        Args:
            results: Dictionary of module results
            target: Target domain
            depth: Scan depth
            modules: List of modules that were run
            output_file: Output file path (optional)
            
        Returns:
            Path to the generated report
        """
        if not output_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"{target}_{timestamp}_report.md"
        elif isinstance(output_file, str):
            output_file = Path(output_file)
        
        # Start with header
        report_content = self._render_header(target, depth, modules)
        
        # Add summary
        report_content += self._render_summary(results, target)
        
        # Add module results
        if "org" in modules and "org" in results:
            report_content += self._render_org_section(results["org"])
        
        if "recon" in modules and "recon" in results:
            report_content += self._render_recon_section(results["recon"])
        
        if "threat" in modules and "threat" in results:
            report_content += self._render_threat_section(results["threat"])
        
        if "typosquat" in modules and "typosquat" in results:
            report_content += self._render_typosquat_section(results["typosquat"])
        
        if "news" in modules and "news" in results:
            report_content += self._render_news_section(results["news"])
        
        # Add footer
        from farsight import __version__
        report_content += self.templates["footer"].format(
            version=__version__,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(report_content)
        
        logger.info(f"Report generated and saved to {output_file}")
        
        return output_file
    
    def convert_to_pdf(self, markdown_file: Path) -> Optional[Path]:
        """
        Convert Markdown report to PDF.
        
        Args:
            markdown_file: Path to Markdown file
            
        Returns:
            Path to PDF file if successful, None otherwise
        """
        if not PDF_SUPPORT:
            logger.warning("PDF conversion libraries not installed. Cannot convert to PDF.")
            return None
        
        try:
            # Create PDF file path
            pdf_file = markdown_file.with_suffix('.pdf')
            
            # Read Markdown content
            with open(markdown_file, 'r') as f:
                markdown_content = f.read()
            
            # First method: weasyprint
            if 'weasyprint' in globals():
                # Convert to HTML
                html = markdown.markdown(
                    markdown_content,
                    extensions=['tables', 'fenced_code']
                )
                
                # Add CSS for better formatting
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        h1 {{ color: #2c3e50; }}
                        h2 {{ color: #3498db; border-bottom: 1px solid #3498db; }}
                        h3 {{ color: #2980b9; }}
                        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #f5f5f5; }}
                        pre {{ background-color: #f8f8f8; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                        code {{ font-family: Consolas, monospace; }}
                    </style>
                </head>
                <body>
                    {html}
                </body>
                </html>
                """
                
                # Convert to PDF
                weasyprint.HTML(string=html).write_pdf(pdf_file)
            
            # Second method: reportlab
            elif 'reportlab' in globals():
                # Create simple PDF with reportlab
                doc = SimpleDocTemplate(str(pdf_file), pagesize=letter)
                styles = getSampleStyleSheet()
                flowables = []
                
                # Split content by headers
                sections = re.split(r'(#+ .*)', markdown_content)
                
                for section in sections:
                    if section.strip():
                        # Process headers
                        if re.match(r'#+ .*', section):
                            level = len(re.match(r'(#+) ', section).group(1))
                            text = section.lstrip('#').strip()
                            style = styles['Heading%d' % min(level, 3)]
                            flowables.append(Paragraph(text, style))
                            flowables.append(Spacer(1, 12))
                        else:
                            # Process paragraphs
                            paragraphs = section.split('\n\n')
                            for p in paragraphs:
                                if p.strip():
                                    # Process lists and code blocks here if needed
                                    flowables.append(Paragraph(p, styles['Normal']))
                                    flowables.append(Spacer(1, 6))
                
                doc.build(flowables)
            
            logger.info(f"PDF report generated and saved to {pdf_file}")
            return pdf_file
        
        except Exception as e:
            logger.error(f"Error converting to PDF: {str(e)}")
            return None
    
    def _render_header(self, target: str, depth: int, modules: List[str]) -> str:
        """Render report header section."""
        return self.templates["header"].format(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            depth=depth,
            modules=", ".join(modules)
        )
    
    def _render_summary(self, results: Dict[str, Dict[str, Any]], target: str) -> str:
        """Render executive summary section."""
        # Extract key metrics for summary
        total_domains = 0
        total_open_ports = 0
        email_security_status = "Unknown"
        additional_points = []
        
        # Get total domains
        if "org" in results and "all_domains" in results["org"]:
            total_domains = len(results["org"]["all_domains"])
        
        # Get open ports
        if "recon" in results and "port_scan" in results["recon"]:
            if "open_ports" in results["recon"]["port_scan"]:
                total_open_ports = results["recon"]["port_scan"]["open_ports"]
        
        # Check email security
        if "recon" in results and "email_security" in results["recon"]:
            email_sec = results["recon"]["email_security"]
            if "spf" in email_sec and "dmarc" in email_sec:
                has_spf = email_sec["spf"].get("found", False)
                has_dmarc = email_sec["dmarc"].get("found", False)
                
                if has_spf and has_dmarc:
                    email_security_status = "Well-protected"
                elif has_spf or has_dmarc:
                    email_security_status = "Partially protected"
                else:
                    email_security_status = "Unprotected"
        
        # Check for threat intelligence findings
        if "threat" in results:
            if "leaks" in results["threat"] and results["threat"]["leaks"]:
                total_leaks = len(results["threat"]["leaks"])
                additional_points.append(f"**{total_leaks}** potential data leaks identified")
        
        # Check for typosquatting
        if "typosquat" in results and "typosquats" in results["typosquat"]:
            total_typosquats = len(results["typosquat"]["typosquats"])
            additional_points.append(f"**{total_typosquats}** typosquatting domains detected")
        
        # Format the additional points
        additional_summary = "\n".join([f"- {point}" for point in additional_points])
        
        return self.templates["summary"].format(
            target=target,
            total_domains=total_domains,
            total_open_ports=total_open_ports,
            email_security_status=email_security_status,
            additional_summary_points=additional_summary
        )
    
    def _render_org_section(self, org_results: Dict[str, Any]) -> str:
        """Render organization discovery section."""
        # Format WHOIS info
        whois_md = "```\n"
        if "whois" in org_results:
            for key, value in org_results["whois"].items():
                if isinstance(value, list):
                    value_str = ", ".join(value)
                else:
                    value_str = str(value)
                whois_md += f"{key.capitalize()}: {value_str}\n"
        else:
            whois_md += "No WHOIS data available."
        whois_md += "```\n"
        
        # Format domains list
        domains_md = ""
        if "all_domains" in org_results and org_results["all_domains"]:
            domains_md = "```\n"
            for domain in org_results["all_domains"]:
                domains_md += f"{domain}\n"
            domains_md += "```\n"
        else:
            domains_md = "No additional domains discovered."
        
        # Format certificate transparency
        ct_md = ""
        if "certificate_transparency" in org_results and org_results["certificate_transparency"]:
            ct_md = "Domains found in certificate transparency logs:\n\n```\n"
            for domain in org_results["certificate_transparency"][:20]:  # Limit to 20 for readability
                ct_md += f"{domain}\n"
            
            if len(org_results["certificate_transparency"]) > 20:
                ct_md += f"... and {len(org_results['certificate_transparency']) - 20} more\n"
            
            ct_md += "```\n"
        else:
            ct_md = "No certificate transparency data available."
        
        return self.templates["org_discovery"].format(
            whois_info=whois_md,
            total_domains=len(org_results.get("all_domains", [])),
            domains_list=domains_md,
            certificate_transparency=ct_md
        )
    
    def _render_recon_section(self, recon_results: Dict[str, Any]) -> str:
        """Render reconnaissance section."""
        # Format DNS records
        dns_md = ""
        if "dns_records" in recon_results and recon_results["dns_records"]:
            dns_md = "### DNS Records\n\n"
            for domain, records in recon_results["dns_records"].items():
                dns_md += f"#### {domain}\n\n"
                for record_type, record_list in records.items():
                    dns_md += f"**{record_type} Records:**\n\n"
                    if record_list:
                        dns_md += "| Type | Data |\n|------|------|\n"
                        for record in record_list:
                            # Extract the most relevant info based on record type
                            if record_type == 'A' or record_type == 'AAAA':
                                data = record.get('ip', 'N/A')
                            elif record_type == 'MX':
                                data = f"{record.get('priority', 'N/A')} {record.get('exchange', 'N/A')}"
                            elif record_type == 'CNAME':
                                data = record.get('target', 'N/A')
                            elif record_type == 'TXT':
                                data = record.get('txt', 'N/A')
                            else:
                                data = record.get('value', 'N/A')
                            
                            dns_md += f"| {record_type} | {data} |\n"
                    else:
                        dns_md += "No records found.\n"
                    dns_md += "\n"
        else:
            dns_md = "No DNS records found."
        
        # Format subdomains
        sub_md = ""
        if "subdomains" in recon_results and recon_results["subdomains"]:
            sub_md = f"Total subdomains discovered: **{len(recon_results['subdomains'])}**\n\n```\n"
            for subdomain in recon_results["subdomains"]:
                sub_md += f"{subdomain}\n"
            sub_md += "```\n"
        else:
            sub_md = "No subdomains discovered."
        
        # Format port scan
        port_md = ""
        if "port_scan" in recon_results and recon_results["port_scan"]:
            scan = recon_results["port_scan"]
            port_md = f"Target IP: **{scan.get('target', 'Unknown')}**\n\n"
            
            if "ports" in scan and scan["ports"]:
                port_md += "| Port | Service | Banner |\n|------|---------|--------|\n"
                for port in scan["ports"]:
                    service = self._get_service_name(port["port"])
                    banner = port.get("banner", "").replace("|", "\\|")[:50]  # Escape pipe chars and truncate
                    port_md += f"| {port['port']} | {service} | {banner} |\n"
            else:
                port_md += "No open ports found."
        else:
            port_md = "No port scan results available."
        
        # Format email security
        email_md = ""
        if "email_security" in recon_results and recon_results["email_security"]:
            sec = recon_results["email_security"]
            email_md = "#### Email Security Findings\n\n"
            
            # SPF status
            spf_status = "✅ Implemented" if sec.get("spf", {}).get("found", False) else "❌ Not implemented"
            email_md += f"**SPF Record:** {spf_status}\n\n"
            
            if "spf" in sec and "record" in sec["spf"] and sec["spf"]["record"]:
                email_md += f"```\n{sec['spf']['record']}\n```\n\n"
            
            # DMARC status
            dmarc_status = "✅ Implemented" if sec.get("dmarc", {}).get("found", False) else "❌ Not implemented"
            email_md += f"**DMARC Record:** {dmarc_status}\n\n"
            
            if "dmarc" in sec and "record" in sec["dmarc"] and sec["dmarc"]["record"]:
                email_md += f"```\n{sec['dmarc']['record']}\n```\n\n"
            
            # Recommendations
            email_md += "**Recommendations:**\n\n"
            recommendations = []
            
            if not sec.get("spf", {}).get("found", False):
                recommendations.append("- Implement SPF to prevent email spoofing")
            
            if not sec.get("dmarc", {}).get("found", False):
                recommendations.append("- Implement DMARC to improve email security and receive reports on email authentication")
            
            if not recommendations:
                recommendations.append("- Email security is well-configured")
            
            email_md += "\n".join(recommendations)
        else:
            email_md = "No email security information available."
        
        return self.templates["recon"].format(
            dns_records=dns_md,
            subdomains=sub_md,
            port_scan=port_md,
            email_security=email_md
        )
    
    def _render_threat_section(self, threat_results: Dict[str, Any]) -> str:
        """Render threat intelligence section."""
        # Format leaks information
        leaks_md = ""
        if "leaks" in threat_results and threat_results["leaks"]:
            leaks_md = "| Source | Type | Date | Details |\n|--------|------|------|--------|\n"
            for leak in threat_results["leaks"]:
                source = leak.get("source", "Unknown")
                leak_type = leak.get("type", "Unknown")
                date = leak.get("date", "Unknown")
                details = leak.get("details", "No details").replace("|", "\\|")[:50]
                leaks_md += f"| {source} | {leak_type} | {date} | {details} |\n"
        else:
            leaks_md = "No data leaks or breaches found."
        
        # Format dark web mentions
        dark_web_md = ""
        if "dark_web" in threat_results and threat_results["dark_web"]:
            dark_web_md = "| Source | Mention | Date |\n|--------|---------|------|\n"
            for mention in threat_results["dark_web"]:
                source = mention.get("source", "Unknown")
                text = mention.get("text", "").replace("|", "\\|")[:50]
                date = mention.get("date", "Unknown")
                dark_web_md += f"| {source} | {text} | {date} |\n"
        else:
            dark_web_md = "No dark web mentions found."
        
        # Format credentials
        creds_md = ""
        if "credentials" in threat_results and threat_results["credentials"]:
            creds_md = f"**Total exposed credentials:** {len(threat_results['credentials'])}\n\n"
            creds_md += "| Email | Source | Date | Password Exposed |\n|-------|--------|------|----------------|\n"
            for cred in threat_results["credentials"]:
                email = cred.get("email", "").replace("@", "[at]")  # Obfuscate email
                source = cred.get("source", "Unknown")
                date = cred.get("date", "Unknown")
                has_password = "Yes" if cred.get("has_password", False) else "No"
                creds_md += f"| {email} | {source} | {date} | {has_password} |\n"
        else:
            creds_md = "No exposed credentials found."
        
        return self.templates["threat_intel"].format(
            leaks=leaks_md,
            dark_web=dark_web_md,
            credentials=creds_md
        )
    
    def _render_typosquat_section(self, typosquat_results: Dict[str, Any]) -> str:
        """Render typosquatting section."""
        typo_md = ""
        if "typosquats" in typosquat_results and typosquat_results["typosquats"]:
            typo_md = "| Domain | Typo Type | Status | Risk Score | DNS |\n|--------|----------|--------|------------|-----|\n"
            for typo in typosquat_results["typosquats"]:
                domain = typo.get("domain", "Unknown")
                typo_type = typo.get("type", "Unknown")
                status = typo.get("status", "Unknown")
                risk = typo.get("risk_score", 0)
                dns = typo.get("has_dns", False)
                dns_text = "✅" if dns else "❌"
                typo_md += f"| {domain} | {typo_type} | {status} | {risk}/100 | {dns_text} |\n"
        else:
            typo_md = "No typosquatting domains detected."
        
        return self.templates["typosquat"].format(
            total_typosquats=len(typosquat_results.get("typosquats", [])),
            typosquats=typo_md
        )
    
    def _render_news_section(self, news_results: Dict[str, Any]) -> str:
        """Render news monitoring section."""
        news_md = ""
        if "articles" in news_results and news_results["articles"]:
            for article in news_results["articles"]:
                title = article.get("title", "Untitled")
                date = article.get("published", "Unknown date")
                url = article.get("url", "#")
                snippet = article.get("snippet", "No snippet available")
                
                news_md += f"### [{title}]({url})\n\n"
                news_md += f"**Published:** {date}\n\n"
                news_md += f"{snippet}\n\n"
                news_md += "---\n\n"
        else:
            news_md = "No recent news articles found."
        
        return self.templates["news"].format(
            news_articles=news_md
        )
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports."""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAP/SSL",
            995: "POP3/SSL",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP Proxy"
        }
        return common_ports.get(port, "Unknown")
