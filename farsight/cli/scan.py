"""Main scan command for FARSIGHT."""

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

app = typer.Typer(help="Run reconnaissance and intelligence gathering scans")


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
                
                # Display summary table of organization findings
                typer.secho("\nDOMAIN SUMMARY:", fg=typer.colors.BRIGHT_CYAN)
                typer.secho("┌─────────────────────┬────────────────────┐", fg=typer.colors.WHITE)
                typer.secho("│ Category            │ Count              │", fg=typer.colors.WHITE)
                typer.secho("├─────────────────────┼────────────────────┤", fg=typer.colors.WHITE)
                typer.secho(f"│ Total Domains       │ {results['org']['total_domains']:<18} │", fg=typer.colors.WHITE)
                if 'certificate_transparency' in results['org']:
                    typer.secho(f"│ Certificate Records │ {len(results['org']['certificate_transparency']):<18} │", fg=typer.colors.WHITE)
                typer.secho("└─────────────────────┴────────────────────┘", fg=typer.colors.WHITE)
                
                # Display a few sample domains if available
                if results['org']['all_domains'] and len(results['org']['all_domains']) > 0:
                    typer.secho("\nSAMPLE DOMAINS:", fg=typer.colors.BRIGHT_CYAN)
                    max_display = min(5, len(results['org']['all_domains']))
                    for i in range(max_display):
                        typer.secho(f"  {results['org']['all_domains'][i]}", fg=typer.colors.GREEN)
    
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
                    if banner and len(banner) > 20:
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
            typer.secho("🛡️ Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("Threat Intelligence", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        async with ThreatIntel(api_manager) as threat_intel:
            results["threat"] = await threat_intel.gather_intelligence(domain, emails, depth)
            
            if verbose:
                typer.secho("✅ ", fg=typer.colors.GREEN, bold=True, nl=False)
                typer.secho("Threat Intelligence complete: ", fg=typer.colors.BRIGHT_BLUE, nl=False)
                typer.secho(f"{results['threat'].get('total_leaks', 0)} leaks found", fg=typer.colors.BRIGHT_GREEN, bold=True)
    
    # Run Typosquatting module
    if "typosquat" in enabled_modules:
        if verbose:
            typer.secho("🎯 Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("Typosquatting Detection", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        async with TyposquatDetector() as typosquat:
            results["typosquat"] = await typosquat.detect(domain, depth)
            
            if verbose:
                typer.secho("✅ ", fg=typer.colors.GREEN, bold=True, nl=False)
                typer.secho("Typosquatting Detection complete: ", fg=typer.colors.BRIGHT_BLUE, nl=False)
                typer.secho(f"{len(results['typosquat'].get('typosquats', []))} typosquats found", fg=typer.colors.BRIGHT_YELLOW, bold=True)
    
    # Run News Monitoring module
    if "news" in enabled_modules:
        if verbose:
            typer.secho("📰 Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho("News Monitoring", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        async with NewsMonitor() as news:
            # Use last 30 days for news by default
            results["news"] = await news.monitor(domain, 30)
            
            if verbose:
                typer.secho("✅ ", fg=typer.colors.GREEN, bold=True, nl=False)
                typer.secho("News Monitoring complete: ", fg=typer.colors.BRIGHT_BLUE, nl=False)
                typer.secho(f"{results['news'].get('total_articles', 0)} articles found", fg=typer.colors.BRIGHT_GREEN, bold=True)
    
    return results


@app.command()
def run(
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
    typer.secho("FARSIGHT RECONNAISSANCE FRAMEWORK", fg=typer.colors.BRIGHT_BLUE, bold=True)
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
        typer.secho("✅ ", nl=False, fg=typer.colors.GREEN, bold=True)
        typer.secho(f"Scan completed in ", nl=False)
        typer.secho(f"{elapsed_time:.2f} seconds", fg=typer.colors.BRIGHT_CYAN, bold=True)
        
        # Display a brief summary of findings
        typer.secho("\n📊 Summary of findings:", fg=typer.colors.BRIGHT_BLUE, bold=True)
        
        if "org" in scan_results and "all_domains" in scan_results["org"]:
            typer.secho(f"  🔍 Domains discovered: ", nl=False)
            typer.secho(f"{len(scan_results['org']['all_domains'])}", fg=typer.colors.BRIGHT_GREEN, bold=True)
        
        if "recon" in scan_results and "subdomains" in scan_results["recon"]:
            typer.secho(f"  🌐 Subdomains found: ", nl=False)
            typer.secho(f"{len(scan_results['recon']['subdomains'])}", fg=typer.colors.BRIGHT_GREEN, bold=True)
            
            if "port_scan" in scan_results["recon"] and "open_ports" in scan_results["recon"]["port_scan"]:
                typer.secho(f"  🔌 Open ports: ", nl=False)
                typer.secho(f"{scan_results['recon']['port_scan']['open_ports']}", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        if "threat" in scan_results:
            threat_data = scan_results["threat"]
            if "total_leaks" in threat_data and threat_data["total_leaks"] > 0:
                typer.secho(f"  ⚠️ Potential data leaks: ", nl=False)
                typer.secho(f"{threat_data['total_leaks']}", fg=typer.colors.BRIGHT_RED, bold=True)
            if "total_credentials" in threat_data and threat_data["total_credentials"] > 0:
                typer.secho(f"  🔑 Exposed credentials: ", nl=False)
                typer.secho(f"{threat_data['total_credentials']}", fg=typer.colors.BRIGHT_RED, bold=True)
        
        if "typosquat" in scan_results and "typosquats" in scan_results["typosquat"]:
            typer.secho(f"  🎯 Typosquatting domains: ", nl=False)
            typer.secho(f"{len(scan_results['typosquat']['typosquats'])}", fg=typer.colors.BRIGHT_YELLOW, bold=True)
        
        typer.secho(f"\n📝 Detailed report saved to: ", nl=False)
        typer.secho(f"{output}", fg=typer.colors.BRIGHT_CYAN, bold=True)
        
    except Exception as e:
        typer.secho(f"❌ Error during scan: ", fg=typer.colors.BRIGHT_RED, bold=True, nl=False)
        typer.secho(f"{str(e)}", fg=typer.colors.RED)
        if verbose:
            import traceback
            typer.secho("\nDetailed error traceback:", fg=typer.colors.YELLOW)
            typer.echo(traceback.format_exc())
        sys.exit(1)