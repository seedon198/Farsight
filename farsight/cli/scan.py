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
    
    # Print status if verbose
    if verbose:
        print(f"Starting scan of {domain} with depth {depth}")
        print(f"Enabled modules: {', '.join(enabled_modules)}")
    
    # Run Organization Discovery module
    if "org" in enabled_modules:
        if verbose:
            print("Starting Organization Discovery module...")
        
        async with OrgDiscovery(api_manager) as org_discovery:
            results["org"] = await org_discovery.discover(domain, depth)
            
            if verbose:
                print(f"Organization Discovery complete: {results['org']['total_domains']} domains found")
    
    # Run Reconnaissance module
    if "recon" in enabled_modules:
        if verbose:
            print("Starting Reconnaissance module...")
        
        recon = Recon(api_manager)
        results["recon"] = await recon.scan(domain, depth)
        
        if verbose:
            print(f"Reconnaissance complete: {results['recon']['total_subdomains']} subdomains found")
    
    # Extract emails for threat intelligence if available
    emails = []
    if "org" in results and "whois" in results["org"] and "emails" in results["org"]["whois"]:
        emails = results["org"]["whois"]["emails"]
    
    # Run Threat Intelligence module
    if "threat" in enabled_modules:
        if verbose:
            print("Starting Threat Intelligence module...")
        
        async with ThreatIntel(api_manager) as threat_intel:
            results["threat"] = await threat_intel.gather_intelligence(domain, emails, depth)
            
            if verbose:
                print(f"Threat Intelligence complete: {results['threat'].get('total_leaks', 0)} leaks found")
    
    # Run Typosquatting module
    if "typosquat" in enabled_modules:
        if verbose:
            print("Starting Typosquatting Detection module...")
        
        async with TyposquatDetector() as typosquat:
            results["typosquat"] = await typosquat.detect(domain, depth)
            
            if verbose:
                print(f"Typosquatting Detection complete: {len(results['typosquat'].get('typosquats', []))} typosquats found")
    
    # Run News Monitoring module
    if "news" in enabled_modules:
        if verbose:
            print("Starting News Monitoring module...")
        
        async with NewsMonitor() as news:
            # Use last 30 days for news by default
            results["news"] = await news.monitor(domain, 30)
            
            if verbose:
                print(f"News Monitoring complete: {results['news'].get('total_articles', 0)} articles found")
    
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
    
    typer.echo(f"FARSIGHT scan initiated against: {domain}")
    typer.echo(f"Output file: {output}")
    typer.echo(f"Enabled modules: {', '.join(enabled_modules)}")
    
    # Check if output file exists and handle --force flag
    if output.exists() and not force:
        typer.echo(f"Output file {output} already exists. Use --force to overwrite.")
        raise typer.Exit(1)
    
    # Setup API manager
    api_manager = APIManager()
    
    # Show API configuration status if verbose
    if verbose:
        apis = get_available_apis()
        typer.echo("API Configuration Status:")
        for api, configured in apis.items():
            status = "✓" if configured else "✗"
            typer.echo(f"  {api}: {status}")
    
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
        typer.echo(f"Scan completed in {elapsed_time:.2f} seconds")
        
        # Display a brief summary of findings
        typer.echo("\nSummary of findings:")
        
        if "org" in scan_results and "all_domains" in scan_results["org"]:
            typer.echo(f"  Domains discovered: {len(scan_results['org']['all_domains'])}")
        
        if "recon" in scan_results and "subdomains" in scan_results["recon"]:
            typer.echo(f"  Subdomains found: {len(scan_results['recon']['subdomains'])}")
            
            if "port_scan" in scan_results["recon"] and "open_ports" in scan_results["recon"]["port_scan"]:
                typer.echo(f"  Open ports: {scan_results['recon']['port_scan']['open_ports']}")
        
        if "threat" in scan_results:
            threat_data = scan_results["threat"]
            if "total_leaks" in threat_data and threat_data["total_leaks"] > 0:
                typer.echo(f"  Potential data leaks: {threat_data['total_leaks']}")
            if "total_credentials" in threat_data and threat_data["total_credentials"] > 0:
                typer.echo(f"  Exposed credentials: {threat_data['total_credentials']}")
        
        if "typosquat" in scan_results and "typosquats" in scan_results["typosquat"]:
            typer.echo(f"  Typosquatting domains: {len(scan_results['typosquat']['typosquats'])}")
        
        typer.echo(f"\nDetailed report saved to: {output}")
        
    except Exception as e:
        typer.secho(f"Error during scan: {str(e)}", fg=typer.colors.RED)
        if verbose:
            import traceback
            typer.echo(traceback.format_exc())
        sys.exit(1)