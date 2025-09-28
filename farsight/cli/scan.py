"""Main scan command for FARSIGHT.

This module contains the core scanning functionality, orchestrating all
reconnaissance modules and generating comprehensive reports.
"""

import typer
from typing import Optional, List, Dict, Any
from pathlib import Path
import asyncio
import time
import sys

from farsight.config import get_config, get_available_apis
from farsight.utils.api_handler import APIManager
from farsight.modules.org_discovery import OrgDiscovery
from farsight.modules.recon import Recon
from farsight.modules.threat_intel import ThreatIntel
from farsight.modules.typosquat import TyposquatDetector
from farsight.modules.news import NewsMonitor
from farsight.modules.report_writer import ReportWriter

# Removed the Typer app wrapper - we'll add the command directly to the main app


async def run_scan(
    domain: str,
    enabled_modules: set,
    depth: int,
    api_manager: APIManager,
    verbose: bool,
    concurrency: int,
    timeout: int
) -> Dict[str, Any]:
    """
    Run the actual scan with all enabled modules.
    
    Args:
        domain: Target domain
        enabled_modules: Set of module names to run
        depth: Scan depth level (1-3)
        api_manager: API manager for API requests
        verbose: Verbose output flag
        concurrency: Maximum concurrent requests
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with results from all modules
    """
    # Initialize results dictionary
    results = {}
    
    # Set timeout in config
    if timeout:
        from farsight.config import DEFAULT_CONFIG
        DEFAULT_CONFIG["timeout"] = timeout
        DEFAULT_CONFIG["max_concurrent_requests"] = concurrency
    
    # Print status if verbose with colorful output but without emojis
    if verbose:
        typer.secho(f"Starting scan of ", fg=typer.colors.BRIGHT_BLUE, bold=True, nl=False)
        typer.secho(f"{domain}", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
        typer.secho(f" with depth ", fg=typer.colors.BRIGHT_BLUE, bold=True, nl=False)
        typer.secho(f"{depth}", fg=typer.colors.BRIGHT_CYAN, bold=True)
        typer.secho(f"Enabled modules: ", fg=typer.colors.BRIGHT_BLUE, bold=True, nl=False)
        typer.secho(f"{', '.join(enabled_modules)}", fg=typer.colors.BRIGHT_MAGENTA, bold=True)
    
    # Run Organization Discovery module
    if "org" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("Organization Discovery", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        async with OrgDiscovery(api_manager) as org_discovery:
            results["org"] = await org_discovery.discover(domain, depth)
        
        if verbose:
            typer.secho("Organization Discovery complete", fg=typer.colors.BRIGHT_BLUE, bold=True)
            
            # Display organization discovery summary table
            typer.secho("\nORGANIZATION SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
            typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
            typer.secho("│ Category            │ Count              │", fg=typer.colors.WHITE)
            typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
            
            # Get domain stats
            related_domains = results['org'].get('related_domains', [])
            discovered_subdomains = results['org'].get('discovered_subdomains', [])
            
            # WHOIS info
            has_whois = results['org'].get('whois', {}) != {}
            
            # Certificate info
            cert_records = len(results['org'].get('certificate_transparency', []))
            
            # Show stats in table
            typer.secho(f"│ Related Domains     │ {len(related_domains):<18} │", fg=typer.colors.WHITE)
            typer.secho(f"│ Discovered Subdomains│ {len(discovered_subdomains):<18} │", fg=typer.colors.WHITE)
            typer.secho(f"│ Certificate Records │ {cert_records:<18} │", fg=typer.colors.WHITE)
            typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
            
            # Display related domains (limit to 5)
            if related_domains:
                typer.secho("\nRELATED DOMAINS:", fg=typer.colors.BRIGHT_CYAN)
                max_display = min(5, len(related_domains))
                
                # Table header
                typer.secho("┌────────────────────────────────────────────────┐", fg=typer.colors.WHITE)
                typer.secho("│ Domain                                         │", fg=typer.colors.WHITE)
                typer.secho("├────────────────────────────────────────────────┤", fg=typer.colors.WHITE)
                
                for i in range(max_display):
                    typer.secho(f"│ {related_domains[i]:<45} │", fg=typer.colors.WHITE)
                
                if len(related_domains) > max_display:
                    typer.secho(f"│ ... and {len(related_domains) - max_display} more domains                │", fg=typer.colors.WHITE)
                    
                typer.secho("└────────────────────────────────────────────────┘", fg=typer.colors.WHITE)
                
            # If WHOIS info is available, display it
            if has_whois and results['org'].get('whois_info', {}).get('org'):
                typer.secho("\nWHOIS INFORMATION:", fg=typer.colors.BRIGHT_CYAN)
                whois_info = results['org']['whois_info']
                
                typer.secho("┌────────────────┬─────────────────────────────────┐", fg=typer.colors.WHITE)
                typer.secho("│ Field           │ Value                            │", fg=typer.colors.WHITE)
                typer.secho("├────────────────┼─────────────────────────────────┤", fg=typer.colors.WHITE)
                
                for field, display_name in [
                    ('org', 'Organization'),
                    ('registrar', 'Registrar'),
                    ('creation_date', 'Created'),
                    ('expiration_date', 'Expires'),
                    ('updated_date', 'Updated'),
                    ('country', 'Country')
                ]:
                    if field in whois_info and whois_info[field]:
                        value = whois_info[field]
                        # Format dates if they are datetime objects
                        if isinstance(value, (datetime.datetime, datetime.date)):
                            value = value.strftime('%Y-%m-%d')
                        elif isinstance(value, list) and value and isinstance(value[0], (datetime.datetime, datetime.date)):
                            value = value[0].strftime('%Y-%m-%d')
                            
                        # Truncate long values
                        if isinstance(value, str) and len(value) > 32:
                            value = value[:29] + '...'
                            
                        typer.secho(f"│ {display_name:<14} │ {value:<32} │", fg=typer.colors.WHITE)
                
                typer.secho("└────────────────┴─────────────────────────────────┘", fg=typer.colors.WHITE)
    
    # Run Reconnaissance module
    if "recon" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("Reconnaissance", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        recon = Recon(api_manager)
        results["recon"] = await recon.scan(domain, depth)
        
        if verbose:
            typer.secho("Reconnaissance complete", fg=typer.colors.BRIGHT_BLUE, bold=True)
            
            # Display asset discovery summary table
            typer.secho("\nASSET SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
            typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
            typer.secho("│ Category            │ Count              │", fg=typer.colors.WHITE)
            typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
            typer.secho(f"│ Subdomains Found    │ {results['recon']['total_subdomains']:<18} │", fg=typer.colors.WHITE)
            
            # Add port scan info if available
            if 'port_scan' in results['recon'] and 'open_ports' in results['recon']['port_scan']:
                typer.secho(f"│ Open Ports          │ {results['recon']['port_scan']['open_ports']:<18} │", fg=typer.colors.WHITE)
            
            # Add DNS records info if available
            if 'dns_records' in results['recon']:
                total_records = sum(len(records.get(record_type, [])) for domain, records in results['recon']['dns_records'].items() for record_type in records)
                typer.secho(f"│ DNS Records         │ {total_records:<18} │", fg=typer.colors.WHITE)
                
            typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
            
            # Display open ports if available
            if 'port_scan' in results['recon'] and 'ports' in results['recon']['port_scan'] and results['recon']['port_scan']['ports']:
                typer.secho("\nOPEN PORTS:", fg=typer.colors.BRIGHT_CYAN)
                typer.secho("┌─────────┬───────────────┬───────────────────────┐", fg=typer.colors.WHITE)
                typer.secho("│ Port    │ Service       │ Banner                 │", fg=typer.colors.WHITE)
                typer.secho("├─────────┼───────────────┼───────────────────────┤", fg=typer.colors.WHITE)
                
                for port_info in results['recon']['port_scan']['ports'][:5]:  # Show first 5 ports
                    port = port_info.get('port', 'N/A')
                    banner = port_info.get('banner', '')
                    if banner is None:
                        banner = ''
                    elif len(banner) > 20:
                        banner = banner[:17] + '...'
                    service = get_service_name(port) if 'get_service_name' in globals() else "-"
                    typer.secho(f"│ {port:<7} │ {service:<13} │ {banner:<23} │", fg=typer.colors.WHITE)
                
                if len(results['recon']['port_scan']['ports']) > 5:
                    typer.secho(f"│ ... and {len(results['recon']['port_scan']['ports'])-5} more ports         │", fg=typer.colors.WHITE)
                    
                typer.secho("└─────────┴───────────────┴───────────────────────┘", fg=typer.colors.WHITE)
            
            # Display a few sample subdomains if available
            if results['recon']['subdomains'] and len(results['recon']['subdomains']) > 0:
                typer.secho("\nSAMPLE SUBDOMAINS:", fg=typer.colors.BRIGHT_CYAN)
                max_display = min(5, len(results['recon']['subdomains']))
                for i in range(max_display):
                    typer.secho(f"  {results['recon']['subdomains'][i]}", fg=typer.colors.GREEN)
    
    # Extract emails for threat intelligence if available
    emails = []
    if "org" in results and "whois" in results["org"] and "emails" in results["org"]["whois"]:
        emails = results["org"]["whois"]["emails"]
    
    # Run Threat Intelligence module
    if "threat" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("Threat Intelligence", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        async with ThreatIntel(api_manager) as threat_intel:
            results["threat"] = await threat_intel.gather_intelligence(domain, emails, depth)
            
            if verbose:
                typer.secho("Threat Intelligence complete", fg=typer.colors.BRIGHT_BLUE, bold=True)
                
                # Display summary table of threat findings
                typer.secho("\nTHREAT SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
                typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
                typer.secho("│ Category            │ Count              │", fg=typer.colors.WHITE)
                typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
                
                # Data leaks
                total_leaks = results['threat'].get('total_leaks', 0)
                leak_color = typer.colors.RED if total_leaks > 0 else typer.colors.WHITE
                typer.secho(f"│ Data Leaks          │ {total_leaks:<18} │", fg=leak_color)
                
                # Exposed credentials
                total_creds = len(results['threat'].get('credentials', []))
                cred_color = typer.colors.RED if total_creds > 0 else typer.colors.WHITE
                typer.secho(f"│ Exposed Credentials │ {total_creds:<18} │", fg=cred_color)
                
                # Dark web mentions
                total_darkweb = len(results['threat'].get('dark_web', []))
                dark_color = typer.colors.YELLOW if total_darkweb > 0 else typer.colors.WHITE
                typer.secho(f"│ Dark Web Mentions   │ {total_darkweb:<18} │", fg=dark_color)
                
                typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
                
                # Display detailed findings if available
                if 'leaks' in results['threat'] and results['threat']['leaks']:
                    typer.secho("\nLEAK DETAILS:", fg=typer.colors.BRIGHT_CYAN)
                    typer.secho("┌────────────────────┬─────────────────┬─────────────────┐", fg=typer.colors.WHITE)
                    typer.secho("│ Source              │ Date              │ Records           │", fg=typer.colors.WHITE)
                    typer.secho("├────────────────────┼─────────────────┼─────────────────┤", fg=typer.colors.WHITE)
                    
                    for i, leak in enumerate(results['threat']['leaks'][:5]):  # Show first 5 leaks
                        source = leak.get('source', 'Unknown')[:18]
                        date = leak.get('date', 'Unknown')[:16]
                        records = str(leak.get('records', 'N/A'))[:16]
                        typer.secho(f"│ {source:<18} │ {date:<17} │ {records:<17} │", fg=typer.colors.WHITE)
                    
                    if len(results['threat']['leaks']) > 5:
                        remaining = len(results['threat']['leaks']) - 5
                        typer.secho(f"│ ... and {remaining} more leaks                           │", fg=typer.colors.WHITE)
                        
                    typer.secho("└────────────────────┴─────────────────┴─────────────────┘", fg=typer.colors.WHITE)
    
    # Run Typosquatting module
    if "typosquat" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("Typosquatting Detection", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        async with TyposquatDetector() as typosquat:
            results["typosquat"] = await typosquat.detect(domain, depth)
            
            if verbose:
                typer.secho("Typosquatting Detection complete", fg=typer.colors.BRIGHT_BLUE, bold=True)
                
                # Display port scan results if available
                if 'port_scan' in results['recon'] and results['recon']['port_scan']:
                    port_scan = results['recon']['port_scan']
                    total_scanned = port_scan.get('total_scanned', 0)
                    domains_with_ports = port_scan.get('domains_with_open_ports', 0)
                    total_open_ports = port_scan.get('total_open_ports', 0)
                    domain_results = port_scan.get('domain_results', {})
                    
                    typer.secho("\nPORT SCAN SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
                    typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
                    typer.secho("│ Category            │ Value              │", fg=typer.colors.WHITE)
                    typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
                    typer.secho(f"│ Domains Scanned     │ {total_scanned:<18} │", fg=typer.colors.WHITE)
                    typer.secho(f"│ Domains with Ports  │ {domains_with_ports:<18} │", fg=typer.colors.WHITE)
                    typer.secho(f"│ Total Open Ports    │ {total_open_ports:<18} │", fg=typer.colors.WHITE)
                    typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
                    
                    # Show up to 5 domains with open ports
                    domains_to_show = []
                    for scan_domain, scan_result in domain_results.items():
                        if scan_result.get('open_ports', 0) > 0:
                            domains_to_show.append((scan_domain, scan_result))
                    
                    if domains_to_show:
                        typer.secho("\nOPEN PORTS BY DOMAIN:", fg=typer.colors.BRIGHT_CYAN)
                        typer.secho("┌────────────────────────────┬────────────────────────┐", fg=typer.colors.WHITE)
                        typer.secho("│ Domain                      │ Open Ports                 │", fg=typer.colors.WHITE)
                        typer.secho("├────────────────────────────┼────────────────────────┤", fg=typer.colors.WHITE)
                        
                        # Display top 5 domains (sort by number of open ports)
                        domains_to_show.sort(key=lambda x: x[1].get('open_ports', 0), reverse=True)
                        max_domains = min(5, len(domains_to_show))
                        
                        for i in range(max_domains):
                            domain_name = domains_to_show[i][0]
                            scan_result = domains_to_show[i][1]
                            
                            # Format open ports
                            open_ports = scan_result.get('open_ports', 0)
                            port_list = scan_result.get('open_port_list', [])
                            
                            if port_list:
                                ports_str = ', '.join(str(port) for port in port_list[:5])
                                if len(port_list) > 5:
                                    ports_str += f" ...({len(port_list) - 5} more)"
                            else:
                                ports_str = str(open_ports)
                            
                            # Truncate domain if too long
                            if len(domain_name) > 26:
                                domain_name = domain_name[:23] + "..."
                            
                            typer.secho(f"│ {domain_name:<26} │ {ports_str:<26} │", fg=typer.colors.WHITE)
                        
                        if len(domains_to_show) > max_domains:
                            typer.secho(f"│ ... and {len(domains_to_show) - max_domains} more domains with open ports      │", fg=typer.colors.WHITE)
                            
                        typer.secho("└────────────────────────────┴────────────────────────┘", fg=typer.colors.WHITE)
                
                # Display summary table of typosquatting findings
                typer.secho("\nTYPOSQUATTING SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
                typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
                typer.secho("│ Category            │ Count              │", fg=typer.colors.WHITE)
                typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
                
                # Get typosquatting stats
                total_typos = len(results['typosquat'].get('typosquats', []))
                total_generated = results['typosquat'].get('total_generated', 0)
                total_active = results['typosquat'].get('total_active', 0)
                
                # Show stats in table
                typo_color = typer.colors.YELLOW if total_typos > 0 else typer.colors.WHITE
                typer.secho(f"│ Typosquats Found    │ {total_typos:<18} │", fg=typo_color)
                typer.secho(f"│ Total Generated     │ {total_generated:<18} │", fg=typer.colors.WHITE)
                typer.secho(f"│ Active Domains      │ {total_active:<18} │", fg=typer.colors.WHITE)
                typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
                
                # Display detailed findings if available
                if results['typosquat'].get('typosquats', []):
                    typer.secho("\nTYPOSQUAT DOMAINS:", fg=typer.colors.BRIGHT_CYAN)
                    typer.secho("┌───────────────────┬────────────────┬───────────┐", fg=typer.colors.WHITE)
                    typer.secho("│ Domain             │ Type              │ Risk Score  │", fg=typer.colors.WHITE)
                    typer.secho("├───────────────────┼────────────────┼───────────┤", fg=typer.colors.WHITE)
                    
                    for i, typo in enumerate(results['typosquat']['typosquats'][:7]):  # Show top 7 typosquats
                        typo_domain = typo.get('domain', 'Unknown')[:17]
                        typo_type = typo.get('type', 'Unknown')[:16]
                        risk_score = typo.get('risk_score', 0)
                        
                        # Color based on risk score
                        if risk_score >= 80:
                            score_color = typer.colors.RED
                        elif risk_score >= 50:
                            score_color = typer.colors.YELLOW
                        else:
                            score_color = typer.colors.GREEN
                            
                        typer.secho(f"│ {typo_domain:<19} │ {typo_type:<16} │ ", nl=False, fg=typer.colors.WHITE)
                        typer.secho(f"{risk_score:<11} │", fg=score_color)
                    
                    if len(results['typosquat']['typosquats']) > 7:
                        remaining = len(results['typosquat']['typosquats']) - 7
                        typer.secho(f"│ ... and {remaining} more typosquatting domains       │", fg=typer.colors.WHITE)
                        
                    typer.secho("└───────────────────┴────────────────┴───────────┘", fg=typer.colors.WHITE)
    
    # Run News Monitoring module
    if "news" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("News Monitoring", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        # Use last 30 days for news by default
        if 'news' in enabled_modules:
            try:
                async with NewsMonitor() as news:
                    results["news"] = await news.monitor(domain, 30)
                    
                    if verbose:
                        typer.secho("News Monitoring complete", fg=typer.colors.BRIGHT_BLUE, bold=True)
                        
                        # Display summary table of news findings
                        typer.secho("\nNEWS MONITORING SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
                        typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
                        typer.secho("│ Category            │ Count              │", fg=typer.colors.WHITE)
                        typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
                        
                        # Articles count
                        total_articles = results['news'].get('total_articles', 0)
                        typer.secho(f"│ Total Articles      │ {total_articles:<18} │", fg=typer.colors.WHITE)
                        
                        # Days monitored
                        days_monitored = results['news'].get('days_monitored', 30)
                        typer.secho(f"│ Days Monitored      │ {days_monitored:<18} │", fg=typer.colors.WHITE)
                        
                        typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
                        
                        # Display recent news articles
                        if 'articles' in results['news'] and results['news']['articles']:
                            typer.secho("\nRECENT NEWS ARTICLES:", fg=typer.colors.BRIGHT_CYAN)
                            typer.secho("┌─────────────────────────────────────────────────────┐", fg=typer.colors.WHITE)
                            
                            for i, article in enumerate(results['news']['articles'][:3]):  # Show top 3 articles
                                title = article.get('title', 'Untitled')
                                publisher = article.get('publisher', article.get('source', 'Unknown'))
                                published = article.get('published', 'Unknown date')
                                url = article.get('url', '')
                                # Get relevance score if available
                                relevance = article.get('relevance_score', '')
                                relevance_info = f" | Relevance: {relevance}" if relevance else ""
                                
                                # Truncate if needed
                                title_display = title
                                if len(title) > 60:
                                    title_display = title[:57] + '...'
                                
                                typer.secho(f"│ {title_display}", fg=typer.colors.WHITE, bold=True)
                                typer.secho(f"│ Source: {publisher} | Published: {published}{relevance_info}", fg=typer.colors.WHITE)
                                if url:
                                    typer.secho(f"│ URL: {url}", fg=typer.colors.WHITE)
                                
                                if i < len(results['news']['articles'][:3]) - 1:  # Add separator if not the last article
                                    typer.secho("├─────────────────────────────────────────────────────┤", fg=typer.colors.WHITE)
                            
                            if len(results['news']['articles']) > 3:
                                remaining = len(results['news']['articles']) - 3
                                typer.secho(f"│ ... and {remaining} more articles", fg=typer.colors.WHITE)
                                
                            typer.secho("└─────────────────────────────────────────────────────┘", fg=typer.colors.WHITE)
            except ImportError:
                typer.secho("GNews library not available. Install with: pip install gnews", fg=typer.colors.BRIGHT_RED)
                results["news"] = {
                    "error": "GNews library not available",
                    "articles": [],
                    "total_articles": 0
                }

    # Display port scan results if available
    if 'recon' in results and 'port_scan' in results['recon'] and results['recon']['port_scan']:
        port_scan = results['recon']['port_scan']
        total_scanned = port_scan.get('total_scanned', 0)
        domains_with_ports = port_scan.get('domains_with_open_ports', 0)
        total_open_ports = port_scan.get('total_open_ports', 0)
        domain_results = port_scan.get('domain_results', {})

        typer.secho("\nPORT SCAN SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
        typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
        typer.secho("│ Category            │ Value              │", fg=typer.colors.WHITE)
        typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
        typer.secho(f"│ Domains Scanned     │ {total_scanned:<18} │", fg=typer.colors.WHITE)
        typer.secho(f"│ Domains with Ports  │ {domains_with_ports:<18} │", fg=typer.colors.WHITE)
        typer.secho(f"│ Total Open Ports    │ {total_open_ports:<18} │", fg=typer.colors.WHITE)
        typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)

        # Show up to 5 domains with open ports
        domains_to_show = []
        for scan_domain, scan_result in domain_results.items():
            if scan_result.get('open_ports', 0) > 0:
                domains_to_show.append((scan_domain, scan_result))

        if domains_to_show:
            typer.secho("\nOPEN PORTS BY DOMAIN:", fg=typer.colors.BRIGHT_CYAN)
            typer.secho("┌────────────────────────────┬────────────────────────┐", fg=typer.colors.WHITE)
            typer.secho("│ Domain                      │ Open Ports                 │", fg=typer.colors.WHITE)
            typer.secho("├────────────────────────────┼────────────────────────┤", fg=typer.colors.WHITE)

            # Display top 5 domains (sort by number of open ports)
            domains_to_show.sort(key=lambda x: x[1].get('open_ports', 0), reverse=True)
            max_domains = min(5, len(domains_to_show))

            for i in range(max_domains):
                domain_name = domains_to_show[i][0]
                scan_result = domains_to_show[i][1]

                # Format open ports
                open_ports = scan_result.get('open_ports', 0)
                port_list = scan_result.get('open_port_list', [])

                if port_list:
                    ports_str = ', '.join(str(port) for port in port_list[:5])
                    if len(port_list) > 5:
                        ports_str += f" ...({len(port_list) - 5} more)"
                else:
                    ports_str = str(open_ports)

                # Truncate domain if too long
                if len(domain_name) > 26:
                    domain_name = domain_name[:23] + "..."

                typer.secho(f"│ {domain_name:<26} │ {ports_str:<26} │", fg=typer.colors.WHITE)

            if len(domains_to_show) > max_domains:
                typer.secho(f"│ ... and {len(domains_to_show) - max_domains} more domains with open ports      │", fg=typer.colors.WHITE)

            typer.secho("└────────────────────────────┴────────────────────────┘", fg=typer.colors.WHITE)


                
        # The news article display is already handled within the NewsMonitor context above
    
    return results


def scan(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    output: Path = typer.Option(
        Path("./report.md"), "--output", "-o", help="Output file path"
    ),
    depth: int = typer.Option(1, "--depth", "-d", help="Scan depth level (1-3)"),
    modules: Optional[List[str]] = typer.Option(
        None,
        "--modules",
        "-m",
        help="Specific modules to run (org, recon, threat, typosquat, news)",
    ),
    all_modules: bool = typer.Option(
        False, "--all", help="Run all available modules"
    ),
    news: bool = typer.Option(False, "--news", help="Include news monitoring"),
    typosquat: bool = typer.Option(
        False, "--typosquat", help="Include typosquatting detection"
    ),
    threat_intel: bool = typer.Option(
        False, "--threat-intel", "-t", help="Include threat intelligence"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    timeout: int = typer.Option(
        get_config("timeout", 30), "--timeout", help="Global timeout for requests in seconds"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force overwrite output file if exists"
    ),
    concurrency: int = typer.Option(
        get_config("max_concurrent_requests", 10),
        "--concurrency",
        "-c",
        help="Maximum concurrent requests",
    ),
):
    """
    Run a comprehensive scan against a target domain.
    
    This will execute reconnaissance, asset discovery, and intelligence gathering
    based on the specified modules and options.
    """
    start_time = time.time()
    
    # Module selection logic
    enabled_modules = set()
    
    # Always include org and recon modules by default
    enabled_modules.add("org")
    enabled_modules.add("recon")
    
    # Add modules based on flags
    if news:
        enabled_modules.add("news")
    if typosquat:
        enabled_modules.add("typosquat")
    if threat_intel:
        enabled_modules.add("threat")
    
    # Override with explicit modules if provided
    if modules:
        # Split any comma-separated module names and flatten the list
        processed_modules = []
        for module in modules:
            if ',' in module:
                processed_modules.extend(module.split(','))
            else:
                processed_modules.append(module)
        enabled_modules = set(processed_modules)
    
    # Run all modules if --all flag is set
    if all_modules:
        enabled_modules = {"org", "recon", "threat", "typosquat", "news"}
    
    # Professional colorful output without emojis
    typer.secho("FARSIGHT Reconnaissance and Threat Intelligence Framework", fg=typer.colors.BRIGHT_BLUE, bold=True)
    typer.secho(f"Scan initiated against: ", nl=False)
    typer.secho(f"{domain}", fg=typer.colors.BRIGHT_GREEN, bold=True)
    typer.secho(f"Output file: ", nl=False)
    typer.secho(f"{output}", fg=typer.colors.BRIGHT_CYAN)
    typer.secho(f"Enabled modules: ", nl=False)
    typer.secho(f"{', '.join(enabled_modules)}", fg=typer.colors.BRIGHT_MAGENTA)
    
    # Check if output file exists and handle --force flag
    if output.exists() and not force:
        typer.echo(f"Output file {output} already exists. Use --force to overwrite.")
        raise typer.Exit(1)
    
    # Setup API manager
    api_manager = APIManager()
    
    # Show API configuration status if verbose
    if verbose:
        apis = get_available_apis()
        typer.secho("API Configuration Status:", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        for api, configured in apis.items():
            if configured:
                status = "✅"
                color = typer.colors.GREEN
            else:
                status = "❌"
                color = typer.colors.RED
            typer.secho(f"  {api}: ", nl=False)
            typer.secho(f"{status}", fg=color)
    
    # Start async event loop for scanning
    try:
        scan_results = asyncio.run(
            run_scan(
                domain=domain,
                enabled_modules=enabled_modules,
                depth=depth,
                api_manager=api_manager,
                verbose=verbose,
                concurrency=concurrency,
                timeout=timeout
            )
        )
        
        # Generate report
        report_writer = ReportWriter()
        report_path = report_writer.generate_report(
            results=scan_results,
            target=domain,
            depth=depth,
            modules=list(enabled_modules),
            output_file=output
        )
        
        # Optionally convert to PDF
        if str(output).endswith('.pdf'):
            pdf_path = report_writer.convert_to_pdf(report_path)
            if pdf_path:
                typer.echo(f"PDF report saved to: {pdf_path}")
            else:
                typer.echo("PDF conversion failed. Markdown report still available.")
        
        # Show summary stats
        elapsed_time = time.time() - start_time
        typer.secho("Scan completed in ", nl=False, fg=typer.colors.BRIGHT_BLUE, bold=True)
        typer.secho(f"{elapsed_time:.2f} seconds", fg=typer.colors.BRIGHT_CYAN, bold=True)
        
        # Display a professional summary table of findings
        typer.secho("\nSUMMARY OF FINDINGS:", fg=typer.colors.BRIGHT_BLUE, bold=True)
        typer.secho("┌───────────────────────────┬─────────────┐", fg=typer.colors.WHITE)
        typer.secho("│ Finding Category               │ Count        │", fg=typer.colors.WHITE)
        typer.secho("├───────────────────────────┼─────────────┤", fg=typer.colors.WHITE)
        
        if "org" in scan_results and "all_domains" in scan_results["org"]:
            typer.secho(f"│ Domains discovered              │ {len(scan_results['org']['all_domains']):<12} │", fg=typer.colors.WHITE)
        
        if "recon" in scan_results and "subdomains" in scan_results["recon"]:
            typer.secho(f"│ Subdomains found               │ {len(scan_results['recon']['subdomains']):<12} │", fg=typer.colors.WHITE)
            
            if "port_scan" in scan_results["recon"] and "open_ports" in scan_results["recon"]["port_scan"]:
                typer.secho(f"│ Open ports                     │ {scan_results['recon']['port_scan']['open_ports']:<12} │", fg=typer.colors.WHITE)
        
        if "threat" in scan_results:
            threat_data = scan_results["threat"]
            if "total_leaks" in threat_data and threat_data["total_leaks"] > 0:
                typer.secho(f"│ Potential data leaks           │ {threat_data['total_leaks']:<12} │", fg=typer.colors.RED if threat_data['total_leaks'] > 0 else typer.colors.WHITE)
            if "total_credentials" in threat_data and threat_data["total_credentials"] > 0:
                typer.secho(f"│ Exposed credentials            │ {threat_data['total_credentials']:<12} │", fg=typer.colors.RED if threat_data['total_credentials'] > 0 else typer.colors.WHITE)
        
        if "typosquat" in scan_results and "typosquats" in scan_results["typosquat"]:
            typer.secho(f"│ Typosquatting domains           │ {len(scan_results['typosquat']['typosquats']):<12} │", fg=typer.colors.YELLOW if len(scan_results['typosquat']['typosquats']) > 0 else typer.colors.WHITE)
            
        if "news" in scan_results and "total_articles" in scan_results["news"]:
            typer.secho(f"│ News articles found             │ {scan_results['news']['total_articles']:<12} │", fg=typer.colors.WHITE)
            
        typer.secho("└───────────────────────────┴─────────────┘", fg=typer.colors.WHITE)
        
        typer.secho(f"\nDetailed report saved to: ", nl=False, fg=typer.colors.BRIGHT_BLUE)
        typer.secho(f"{output}", fg=typer.colors.BRIGHT_CYAN, bold=True)
        
    except Exception as e:
        typer.secho(f"ERROR: ", fg=typer.colors.BRIGHT_RED, bold=True, nl=False)
        typer.secho(f"{str(e)}", fg=typer.colors.RED)
        if verbose:
            import traceback
            typer.secho("\nDetailed error traceback:", fg=typer.colors.YELLOW)
            typer.echo(traceback.format_exc())
        sys.exit(1)