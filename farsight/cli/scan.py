"""Main scan command for FARSIGHT.

This module contains the core scanning functionality, orchestrating all
reconnaissance modules and generating comprehensive reports.
"""

import typer
from typing import Optional, List, Dict, Any
from pathlib import Path
import asyncio
import datetime
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
from farsight.utils.common import get_service_name
from farsight.utils import display

# Removed the Typer app wrapper - we'll add the command directly to the main app


async def run_scan(
    domain: str,
    enabled_modules: set,
    depth: int,
    api_manager: APIManager,
    verbose: bool,
    concurrency: int,
    timeout: int,
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
        typer.secho(
            "Starting scan of ", fg=typer.colors.BRIGHT_BLUE, bold=True, nl=False
        )
        typer.secho(f"{domain}", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False)
        typer.secho(" with depth ", fg=typer.colors.BRIGHT_BLUE, bold=True, nl=False)
        typer.secho(f"{depth}", fg=typer.colors.BRIGHT_CYAN, bold=True)
        typer.secho(
            "Enabled modules: ", fg=typer.colors.BRIGHT_BLUE, bold=True, nl=False
        )
        typer.secho(
            f"{', '.join(enabled_modules)}", fg=typer.colors.BRIGHT_MAGENTA, bold=True
        )

    # Run Organization Discovery module
    if "org" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho(
                "Organization Discovery",
                fg=typer.colors.BRIGHT_GREEN,
                bold=True,
                nl=False,
            )
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)

        async with OrgDiscovery(api_manager) as org_discovery:
            results["org"] = await org_discovery.discover(domain, depth)

        if verbose:
            typer.secho(
                "Organization Discovery complete",
                fg=typer.colors.BRIGHT_BLUE,
                bold=True,
            )

            # Display organization discovery summary
            # Get domain stats
            related_domains = results["org"].get("related_domains", [])
            discovered_subdomains = results["org"].get("discovered_subdomains", [])

            # WHOIS info
            has_whois = results["org"].get("whois", {}) != {}

            # Certificate info
            cert_records = len(results["org"].get("certificate_transparency", []))

            display.section("ORGANIZATION SUMMARY")
            display.kv_rows(
                [
                    ("Related Domains", len(related_domains), None),
                    ("Discovered Subdomains", len(discovered_subdomains), None),
                    ("Certificate Records", cert_records, None),
                ]
            )

            # Display related domains (limit to 5)
            if related_domains:
                display.section("RELATED DOMAINS")
                max_display = min(5, len(related_domains))
                display.item_list(related_domains[:max_display])
                if len(related_domains) > max_display:
                    display.more(len(related_domains) - max_display, "domains")

            # If WHOIS info is available, display it
            if has_whois and results["org"].get("whois_info", {}).get("org"):
                whois_info = results["org"]["whois_info"]

                whois_rows = []
                for field, field_display_name in [
                    ("org", "Organization"),
                    ("registrar", "Registrar"),
                    ("creation_date", "Created"),
                    ("expiration_date", "Expires"),
                    ("updated_date", "Updated"),
                    ("country", "Country"),
                ]:
                    if field in whois_info and whois_info[field]:
                        value = whois_info[field]
                        # Format dates if they are datetime objects
                        if isinstance(value, (datetime.datetime, datetime.date)):
                            value = value.strftime("%Y-%m-%d")
                        elif (
                            isinstance(value, list)
                            and value
                            and isinstance(value[0], (datetime.datetime, datetime.date))
                        ):
                            value = value[0].strftime("%Y-%m-%d")

                        # Truncate long values
                        if isinstance(value, str) and len(value) > 32:
                            value = value[:29] + "..."

                        whois_rows.append((field_display_name, value, None))

                display.section("WHOIS INFORMATION")
                display.kv_rows(whois_rows)

    # Run Reconnaissance module
    if "recon" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho(
                "Reconnaissance", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False
            )
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)

        recon = Recon(api_manager)
        results["recon"] = await recon.scan(domain, depth)

        if verbose:
            typer.secho(
                "Reconnaissance complete", fg=typer.colors.BRIGHT_BLUE, bold=True
            )

            # Display asset discovery summary
            asset_rows = [
                (
                    "Subdomains Found",
                    results["recon"]["total_subdomains"],
                    None,
                )
            ]

            # Add port scan info if available
            if (
                "port_scan" in results["recon"]
                and "open_ports" in results["recon"]["port_scan"]
            ):
                asset_rows.append(
                    ("Open Ports", results["recon"]["port_scan"]["open_ports"], None)
                )

            # Add DNS records info if available
            if "dns_records" in results["recon"]:
                total_records = sum(
                    len(records.get(record_type, []))
                    for domain, records in results["recon"]["dns_records"].items()
                    for record_type in records
                )
                asset_rows.append(("DNS Records", total_records, None))

            display.section("ASSET SUMMARY")
            display.kv_rows(asset_rows)

            # Display open ports if available
            if (
                "port_scan" in results["recon"]
                and "ports" in results["recon"]["port_scan"]
                and results["recon"]["port_scan"]["ports"]
            ):
                port_rows = []
                for port_info in results["recon"]["port_scan"]["ports"][
                    :5
                ]:  # Show first 5 ports
                    port = port_info.get("port", "N/A")
                    banner = port_info.get("banner", "")
                    if banner is None:
                        banner = ""
                    elif len(banner) > 20:
                        banner = banner[:17] + "..."
                    service = get_service_name(port) if port != "N/A" else "-"
                    port_rows.append((port, service, banner))

                display.section("OPEN PORTS")
                display.columns(["Port", "Service", "Banner"], port_rows)

                if len(results["recon"]["port_scan"]["ports"]) > 5:
                    display.more(
                        len(results["recon"]["port_scan"]["ports"]) - 5, "ports"
                    )

            # Display a few sample subdomains if available
            if (
                results["recon"]["subdomains"]
                and len(results["recon"]["subdomains"]) > 0
            ):
                typer.secho("\nSAMPLE SUBDOMAINS:", fg=typer.colors.BRIGHT_CYAN)
                max_display = min(5, len(results["recon"]["subdomains"]))
                for i in range(max_display):
                    typer.secho(
                        f"  {results['recon']['subdomains'][i]}", fg=typer.colors.GREEN
                    )

    # Extract emails for threat intelligence if available
    emails = []
    if (
        "org" in results
        and "whois" in results["org"]
        and "emails" in results["org"]["whois"]
    ):
        emails = results["org"]["whois"]["emails"]

    # Run Threat Intelligence module
    if "threat" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho(
                "Threat Intelligence", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False
            )
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)

        async with ThreatIntel(api_manager) as threat_intel:
            results["threat"] = await threat_intel.gather_intelligence(
                domain, emails, depth
            )

            if verbose:
                typer.secho(
                    "Threat Intelligence complete",
                    fg=typer.colors.BRIGHT_BLUE,
                    bold=True,
                )

                # Display summary of threat findings
                # Data leaks
                total_leaks = results["threat"].get("total_leaks", 0)
                leak_color = typer.colors.RED if total_leaks > 0 else None

                # Exposed credentials
                total_creds = len(results["threat"].get("credentials", []))
                cred_color = typer.colors.RED if total_creds > 0 else None

                # Dark web mentions
                total_darkweb = len(results["threat"].get("dark_web", []))
                dark_color = typer.colors.YELLOW if total_darkweb > 0 else None

                display.section("THREAT SUMMARY")
                display.kv_rows(
                    [
                        ("Data Leaks", total_leaks, leak_color),
                        ("Exposed Credentials", total_creds, cred_color),
                        ("Dark Web Mentions", total_darkweb, dark_color),
                    ]
                )

                # Display detailed findings if available
                if "leaks" in results["threat"] and results["threat"]["leaks"]:
                    leak_rows = []
                    for leak in results["threat"]["leaks"][:5]:  # Show first 5 leaks
                        source = leak.get("source", "Unknown")[:18]
                        date = leak.get("date", "Unknown")[:16]
                        records = str(leak.get("records", "N/A"))[:16]
                        leak_rows.append((source, date, records))

                    display.section("LEAK DETAILS")
                    display.columns(["Source", "Date", "Records"], leak_rows)

                    if len(results["threat"]["leaks"]) > 5:
                        display.more(len(results["threat"]["leaks"]) - 5, "leaks")

    # Run Typosquatting module
    if "typosquat" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho(
                "Typosquatting Detection",
                fg=typer.colors.BRIGHT_GREEN,
                bold=True,
                nl=False,
            )
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)

        async with TyposquatDetector() as typosquat:
            results["typosquat"] = await typosquat.detect(domain, depth)

            if verbose:
                typer.secho(
                    "Typosquatting Detection complete",
                    fg=typer.colors.BRIGHT_BLUE,
                    bold=True,
                )

                # Display port scan results if available
                if "port_scan" in results["recon"] and results["recon"]["port_scan"]:
                    port_scan = results["recon"]["port_scan"]
                    total_scanned = port_scan.get("total_scanned", 0)
                    domains_with_ports = port_scan.get("domains_with_open_ports", 0)
                    total_open_ports = port_scan.get("total_open_ports", 0)
                    domain_results = port_scan.get("domain_results", {})

                    display.section("PORT SCAN SUMMARY")
                    display.kv_rows(
                        [
                            ("Domains Scanned", total_scanned, None),
                            ("Domains with Ports", domains_with_ports, None),
                            ("Total Open Ports", total_open_ports, None),
                        ]
                    )

                    # Show up to 5 domains with open ports
                    domains_to_show = []
                    for scan_domain, scan_result in domain_results.items():
                        if scan_result.get("open_ports", 0) > 0:
                            domains_to_show.append((scan_domain, scan_result))

                    if domains_to_show:
                        # Display top 5 domains (sort by number of open ports)
                        domains_to_show.sort(
                            key=lambda x: x[1].get("open_ports", 0), reverse=True
                        )
                        max_domains = min(5, len(domains_to_show))

                        domain_port_rows = []
                        for i in range(max_domains):
                            domain_name = domains_to_show[i][0]
                            scan_result = domains_to_show[i][1]

                            # Format open ports
                            open_ports = scan_result.get("open_ports", 0)
                            port_list = scan_result.get("open_port_list", [])

                            if port_list:
                                ports_str = ", ".join(
                                    str(port) for port in port_list[:5]
                                )
                                if len(port_list) > 5:
                                    ports_str += f" ...({len(port_list) - 5} more)"
                            else:
                                ports_str = str(open_ports)

                            # Truncate domain if too long
                            if len(domain_name) > 26:
                                domain_name = domain_name[:23] + "..."

                            domain_port_rows.append((domain_name, ports_str))

                        display.section("OPEN PORTS BY DOMAIN")
                        display.columns(["Domain", "Open Ports"], domain_port_rows)

                        if len(domains_to_show) > max_domains:
                            display.more(
                                len(domains_to_show) - max_domains,
                                "domains with open ports",
                            )

                # Get typosquatting stats
                total_typos = len(results["typosquat"].get("typosquats", []))
                total_generated = results["typosquat"].get("total_generated", 0)
                total_active = results["typosquat"].get("total_active", 0)

                typo_color = typer.colors.YELLOW if total_typos > 0 else None

                display.section("TYPOSQUATTING SUMMARY")
                display.kv_rows(
                    [
                        ("Typosquats Found", total_typos, typo_color),
                        ("Total Generated", total_generated, None),
                        ("Active Domains", total_active, None),
                    ]
                )

                # Display detailed findings if available
                if results["typosquat"].get("typosquats", []):
                    typo_rows = []
                    row_colors = []
                    for typo in results["typosquat"]["typosquats"][
                        :7
                    ]:  # Show top 7 typosquats
                        typo_domain = typo.get("domain", "Unknown")[:17]
                        typo_type = typo.get("type", "Unknown")[:16]
                        risk_score = typo.get("risk_score", 0)

                        # Color based on risk score
                        if risk_score >= 80:
                            score_color = typer.colors.RED
                        elif risk_score >= 50:
                            score_color = typer.colors.YELLOW
                        else:
                            score_color = typer.colors.GREEN

                        typo_rows.append((typo_domain, typo_type, risk_score))
                        row_colors.append(score_color)

                    display.section("TYPOSQUAT DOMAINS")
                    display.columns(
                        ["Domain", "Type", "Risk Score"], typo_rows, row_colors
                    )

                    if len(results["typosquat"]["typosquats"]) > 7:
                        remaining = len(results["typosquat"]["typosquats"]) - 7
                        display.more(remaining, "typosquatting domains")

    # Run News Monitoring module
    if "news" in enabled_modules:
        if verbose:
            typer.secho("Starting ", fg=typer.colors.BRIGHT_YELLOW, bold=True, nl=False)
            typer.secho(
                "News Monitoring", fg=typer.colors.BRIGHT_GREEN, bold=True, nl=False
            )
            typer.secho(" module...", fg=typer.colors.BRIGHT_YELLOW, bold=True)

        # Use last 30 days for news by default
        if "news" in enabled_modules:
            try:
                async with NewsMonitor() as news:
                    results["news"] = await news.monitor(domain, 30)

                    if verbose:
                        typer.secho(
                            "News Monitoring complete",
                            fg=typer.colors.BRIGHT_BLUE,
                            bold=True,
                        )

                        # Display summary of news findings
                        total_articles = results["news"].get("total_articles", 0)
                        days_monitored = results["news"].get("days_monitored", 30)

                        display.section("NEWS MONITORING SUMMARY")
                        display.kv_rows(
                            [
                                ("Total Articles", total_articles, None),
                                ("Days Monitored", days_monitored, None),
                            ]
                        )

                        # Display recent news articles
                        if (
                            "articles" in results["news"]
                            and results["news"]["articles"]
                        ):
                            display.section("RECENT NEWS ARTICLES")

                            articles_to_show = results["news"]["articles"][:3]
                            for i, article in enumerate(
                                articles_to_show
                            ):  # Show top 3 articles
                                title = article.get("title", "Untitled")
                                publisher = article.get(
                                    "publisher", article.get("source", "Unknown")
                                )
                                published = article.get("published", "Unknown date")
                                url = article.get("url", "")
                                # Get relevance score if available
                                relevance = article.get("relevance_score", "")
                                relevance_info = (
                                    f" | Relevance: {relevance}" if relevance else ""
                                )

                                # Truncate if needed
                                title_display = title
                                if len(title) > 60:
                                    title_display = title[:57] + "..."

                                if i > 0:
                                    typer.echo()
                                typer.secho(
                                    f"  {title_display}",
                                    fg=typer.colors.WHITE,
                                    bold=True,
                                )
                                typer.secho(
                                    f"  Source: {publisher} | Published: {published}{relevance_info}",
                                    fg=typer.colors.BRIGHT_BLACK,
                                )
                                if url:
                                    typer.secho(
                                        f"  URL: {url}", fg=typer.colors.BRIGHT_BLACK
                                    )

                            if len(results["news"]["articles"]) > 3:
                                remaining = len(results["news"]["articles"]) - 3
                                typer.echo()
                                display.more(remaining, "articles")
            except ImportError:
                typer.secho(
                    "GNews library not available. Install with: pip install gnews",
                    fg=typer.colors.BRIGHT_RED,
                )
                results["news"] = {
                    "error": "GNews library not available",
                    "articles": [],
                    "total_articles": 0,
                }

    # Display port scan results if available
    if (
        "recon" in results
        and "port_scan" in results["recon"]
        and results["recon"]["port_scan"]
    ):
        port_scan = results["recon"]["port_scan"]
        total_scanned = port_scan.get("total_scanned", 0)
        domains_with_ports = port_scan.get("domains_with_open_ports", 0)
        total_open_ports = port_scan.get("total_open_ports", 0)
        domain_results = port_scan.get("domain_results", {})

        display.section("PORT SCAN SUMMARY")
        display.kv_rows(
            [
                ("Domains Scanned", total_scanned, None),
                ("Domains with Ports", domains_with_ports, None),
                ("Total Open Ports", total_open_ports, None),
            ]
        )

        # Show up to 5 domains with open ports
        domains_to_show = []
        for scan_domain, scan_result in domain_results.items():
            if scan_result.get("open_ports", 0) > 0:
                domains_to_show.append((scan_domain, scan_result))

        if domains_to_show:
            # Display top 5 domains (sort by number of open ports)
            domains_to_show.sort(key=lambda x: x[1].get("open_ports", 0), reverse=True)
            max_domains = min(5, len(domains_to_show))

            domain_port_rows = []
            for i in range(max_domains):
                domain_name = domains_to_show[i][0]
                scan_result = domains_to_show[i][1]

                # Format open ports
                open_ports = scan_result.get("open_ports", 0)
                port_list = scan_result.get("open_port_list", [])

                if port_list:
                    ports_str = ", ".join(str(port) for port in port_list[:5])
                    if len(port_list) > 5:
                        ports_str += f" ...({len(port_list) - 5} more)"
                else:
                    ports_str = str(open_ports)

                # Truncate domain if too long
                if len(domain_name) > 26:
                    domain_name = domain_name[:23] + "..."

                domain_port_rows.append((domain_name, ports_str))

            display.section("OPEN PORTS BY DOMAIN")
            display.columns(["Domain", "Open Ports"], domain_port_rows)

            if len(domains_to_show) > max_domains:
                display.more(
                    len(domains_to_show) - max_domains, "domains with open ports"
                )

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
    all_modules: bool = typer.Option(False, "--all", help="Run all available modules"),
    news: bool = typer.Option(False, "--news", help="Include news monitoring"),
    typosquat: bool = typer.Option(
        False, "--typosquat", help="Include typosquatting detection"
    ),
    threat_intel: bool = typer.Option(
        False, "--threat-intel", "-t", help="Include threat intelligence"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    timeout: int = typer.Option(
        get_config("timeout", 30),
        "--timeout",
        help="Global timeout for requests in seconds",
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
            if "," in module:
                processed_modules.extend(module.split(","))
            else:
                processed_modules.append(module)
        enabled_modules = set(processed_modules)

    # Run all modules if --all flag is set
    if all_modules:
        enabled_modules = {"org", "recon", "threat", "typosquat", "news"}

    # Professional colorful output without emojis
    typer.secho(
        "FARSIGHT Reconnaissance and Threat Intelligence Framework",
        fg=typer.colors.BRIGHT_BLUE,
        bold=True,
    )
    typer.secho("Scan initiated against: ", nl=False)
    typer.secho(f"{domain}", fg=typer.colors.BRIGHT_GREEN, bold=True)
    typer.secho("Output file: ", nl=False)
    typer.secho(f"{output}", fg=typer.colors.BRIGHT_CYAN)
    typer.secho("Enabled modules: ", nl=False)
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
        typer.secho(
            "API Configuration Status:", fg=typer.colors.BRIGHT_YELLOW, bold=True
        )
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
                timeout=timeout,
            )
        )

        # Generate report
        report_writer = ReportWriter()
        report_path = report_writer.generate_report(
            results=scan_results,
            target=domain,
            depth=depth,
            modules=list(enabled_modules),
            output_file=output,
        )

        # Optionally convert to PDF
        if str(output).endswith(".pdf"):
            pdf_path = report_writer.convert_to_pdf(report_path)
            if pdf_path:
                typer.echo(f"PDF report saved to: {pdf_path}")
            else:
                typer.echo("PDF conversion failed. Markdown report still available.")

        # Show summary stats
        elapsed_time = time.time() - start_time
        typer.secho(
            "Scan completed in ", nl=False, fg=typer.colors.BRIGHT_BLUE, bold=True
        )
        typer.secho(
            f"{elapsed_time:.2f} seconds", fg=typer.colors.BRIGHT_CYAN, bold=True
        )

        # Display a summary of findings
        finding_rows = []

        if "org" in scan_results and "all_domains" in scan_results["org"]:
            finding_rows.append(
                (
                    "Domains discovered",
                    len(scan_results["org"]["all_domains"]),
                    None,
                )
            )

        if "recon" in scan_results and "subdomains" in scan_results["recon"]:
            finding_rows.append(
                (
                    "Subdomains found",
                    len(scan_results["recon"]["subdomains"]),
                    None,
                )
            )

            if (
                "port_scan" in scan_results["recon"]
                and "open_ports" in scan_results["recon"]["port_scan"]
            ):
                finding_rows.append(
                    (
                        "Open ports",
                        scan_results["recon"]["port_scan"]["open_ports"],
                        None,
                    )
                )

        if "threat" in scan_results:
            threat_data = scan_results["threat"]
            if "total_leaks" in threat_data and threat_data["total_leaks"] > 0:
                finding_rows.append(
                    (
                        "Potential data leaks",
                        threat_data["total_leaks"],
                        typer.colors.RED,
                    )
                )
            if (
                "total_credentials" in threat_data
                and threat_data["total_credentials"] > 0
            ):
                finding_rows.append(
                    (
                        "Exposed credentials",
                        threat_data["total_credentials"],
                        typer.colors.RED,
                    )
                )

        if "typosquat" in scan_results and "typosquats" in scan_results["typosquat"]:
            typosquat_count = len(scan_results["typosquat"]["typosquats"])
            finding_rows.append(
                (
                    "Typosquatting domains",
                    typosquat_count,
                    typer.colors.YELLOW if typosquat_count > 0 else None,
                )
            )

        if "news" in scan_results and "total_articles" in scan_results["news"]:
            finding_rows.append(
                (
                    "News articles found",
                    scan_results["news"]["total_articles"],
                    None,
                )
            )

        typer.secho("\nSUMMARY OF FINDINGS", fg=typer.colors.BRIGHT_BLUE, bold=True)
        display.kv_rows(finding_rows)

        typer.secho(
            "\nDetailed report saved to: ", nl=False, fg=typer.colors.BRIGHT_BLUE
        )
        typer.secho(f"{output}", fg=typer.colors.BRIGHT_CYAN, bold=True)

    except Exception as e:
        typer.secho("ERROR: ", fg=typer.colors.BRIGHT_RED, bold=True, nl=False)
        typer.secho(f"{str(e)}", fg=typer.colors.RED)
        if verbose:
            import traceback

            typer.secho("\nDetailed error traceback:", fg=typer.colors.YELLOW)
            typer.echo(traceback.format_exc())
        sys.exit(1)
