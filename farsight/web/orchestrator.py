"""Event-emitting scan orchestrator for the web UI.

Mirrors farsight.cli.scan.run_scan()'s module sequence and wiring
without importing or modifying that module, so the CLI path
(stabilized separately) carries zero additional risk from this code.

Deviates from run_scan() in one deliberate way: each module runs in
its own try/except, so one module failing doesn't abort the whole
scan. A live demo should degrade gracefully, not die on stage because
one network call timed out.

The summary builders, MODULE_ORDER, and finalize_scan() are exposed
(no leading underscore) because farsight.web.replay reuses them to
emit an identical event sequence when replaying a captured fixture -
the frontend should not be able to tell the difference.
"""

import asyncio
from typing import Any, Awaitable, Callable, Dict, List, Optional

from farsight.modules.attack_surface import AttackSurface
from farsight.modules.news import NewsMonitor
from farsight.modules.org_discovery import OrgDiscovery
from farsight.modules.recon import Recon
from farsight.modules.report_writer import ReportWriter
from farsight.modules.threat_intel import ThreatIntel
from farsight.modules.typosquat import TyposquatDetector
from farsight.utils.api_handler import APIManager
from farsight.utils.common import logger
from farsight.web.events import EventType, ScanEvent
from farsight.web.scan_manager import scan_manager

EmitFn = Callable[[ScanEvent], Awaitable[None]]

MODULE_ORDER = ["org", "recon", "attack_surface", "threat", "typosquat", "news"]


def _collect_known_ips(recon_result: Dict[str, Any]) -> List[str]:
    """Pull resolved IPs out of the recon module's DNS results, for the
    attack surface module's cloud-IP tagging to check beyond what it
    discovers itself via ASN/netblock lookups."""
    known_ips = set()
    for domain_records in (recon_result or {}).get("dns_records", {}).values():
        for record in domain_records.get("A", []):
            if record.get("ip"):
                known_ips.add(record["ip"])
    return list(known_ips)


def org_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_related_domains": result.get("total_related_domains", 0),
        "total_subdomains": result.get("total_subdomains", 0),
        "whois_found": bool(result.get("whois")),
        # Full lists (not just counts) so the frontend can render the
        # attack-surface graph without a second round trip.
        "related_domains": (result.get("related_domains") or [])[:200],
        "discovered_subdomains": (result.get("discovered_subdomains") or [])[:200],
    }


def recon_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    port_scan = result.get("port_scan") or {}
    email_security = result.get("email_security") or {}
    return {
        "total_subdomains": result.get("total_subdomains", 0),
        "total_open_ports": port_scan.get("total_open_ports", 0),
        "spf_found": bool((email_security.get("spf") or {}).get("found")),
        "dmarc_found": bool((email_security.get("dmarc") or {}).get("found")),
        "subdomains": (result.get("subdomains") or [])[:200],
    }


def attack_surface_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_asns": result.get("total_asns", 0),
        "total_netblocks": result.get("total_netblocks", 0),
        "total_exposed_buckets": result.get("total_exposed_buckets", 0),
        "cloud_summary": result.get("cloud_summary", {}),
        # Full (capped) lists so the frontend can render finding details,
        # not just the roll-up counts above.
        "asns": (result.get("asns") or [])[:100],
        "netblocks": (result.get("netblocks") or [])[:200],
        "exposed_buckets": (result.get("exposed_buckets") or [])[:50],
    }


def threat_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_leaks": result.get("total_leaks", 0),
        "total_dark_web": result.get("total_dark_web", 0),
        "total_credentials": result.get("total_credentials", 0),
        "total_emails_found": result.get("total_emails_found", 0),
        "total_intelx_phonebook": result.get("total_intelx_phonebook", 0),
        # Full (capped) lists so the frontend can render finding details,
        # not just the roll-up counts above.
        "leaks": (result.get("leaks") or [])[:50],
        "dark_web": (result.get("dark_web") or [])[:50],
        "credentials": (result.get("credentials") or [])[:50],
        "intelx_phonebook": (result.get("intelx_phonebook") or [])[:50],
    }


def typosquat_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    typosquats = result.get("typosquats") or []
    return {
        "total_generated": result.get("total_generated", 0),
        "total_active": result.get("total_active", 0),
        "top_risk": typosquats[:5],
        # Fuller list (already sorted by risk_score desc) for the graph
        # and the typosquat "gotcha" panel; capped defensively.
        "typosquats": typosquats[:100],
    }


def news_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_articles": result.get("total_articles", 0),
        "days_monitored": result.get("days_monitored", 0),
    }


SUMMARY_BUILDERS = {
    "org": org_summary,
    "recon": recon_summary,
    "attack_surface": attack_surface_summary,
    "threat": threat_summary,
    "typosquat": typosquat_summary,
    "news": news_summary,
}


async def finalize_scan(
    results: Dict[str, Any],
    domain: str,
    depth: int,
    requested_modules: List[str],
    emit: EmitFn,
    replay: bool = False,
) -> Optional[str]:
    """Generate the report (if any modules produced results) and emit
    REPORT_READY + SCAN_COMPLETED. Shared by the live orchestrator and
    the offline replay engine so report-writing logic lives in one
    place, and both paths behave identically from the frontend's view.
    """
    report_id = None
    if results:
        writer = ReportWriter()
        report_path = await asyncio.to_thread(
            writer.generate_report,
            results=results,
            target=domain,
            depth=depth,
            modules=list(results.keys()),
            output_file=None,
        )
        pdf_path = await asyncio.to_thread(writer.convert_to_pdf, report_path)
        report_id = scan_manager.register_report(report_path, pdf_path)
        await emit(
            ScanEvent(
                type=EventType.REPORT_READY,
                data={"report_id": report_id, "has_pdf": pdf_path is not None},
            )
        )

    completed_data: Dict[str, Any] = {
        "completed_modules": list(results.keys()),
        "failed_modules": [m for m in requested_modules if m not in results],
        "report_id": report_id,
    }
    if replay:
        completed_data["replay"] = True

    await emit(ScanEvent(type=EventType.SCAN_COMPLETED, data=completed_data))
    return report_id


async def run_scan_with_events(
    domain: str,
    depth: int,
    modules: List[str],
    emit: EmitFn,
) -> Dict[str, Any]:
    """Run a scan against `domain`, emitting a ScanEvent at each step."""
    results: Dict[str, Any] = {}
    api_manager = APIManager()
    enabled = set(modules)

    await emit(
        ScanEvent(
            type=EventType.SCAN_STARTED, data={"domain": domain, "modules": modules}
        )
    )

    try:
        if "org" in enabled:
            await emit(ScanEvent(type=EventType.MODULE_STARTED, module="org"))
            try:
                async with OrgDiscovery(api_manager) as org_discovery:
                    results["org"] = await org_discovery.discover(domain, depth)
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_COMPLETED,
                        module="org",
                        data=org_summary(results["org"]),
                    )
                )
            except Exception as e:
                logger.exception("org module failed")
                await emit(
                    ScanEvent(type=EventType.MODULE_ERROR, module="org", message=str(e))
                )

        if "recon" in enabled:
            await emit(ScanEvent(type=EventType.MODULE_STARTED, module="recon"))
            try:
                recon = Recon(api_manager)
                results["recon"] = await recon.scan(domain, depth)
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_COMPLETED,
                        module="recon",
                        data=recon_summary(results["recon"]),
                    )
                )
            except Exception as e:
                logger.exception("recon module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR, module="recon", message=str(e)
                    )
                )

        if "attack_surface" in enabled:
            await emit(
                ScanEvent(type=EventType.MODULE_STARTED, module="attack_surface")
            )
            try:
                org_name = results.get("org", {}).get("whois", {}).get("org")
                subsidiaries = results.get("org", {}).get("acquisitions", [])
                known_ips = _collect_known_ips(results.get("recon", {}))
                async with AttackSurface(api_manager) as attack_surface:
                    results["attack_surface"] = await attack_surface.discover(
                        domain,
                        org_name=org_name,
                        subsidiaries=subsidiaries,
                        known_ips=known_ips,
                        depth=depth,
                    )
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_COMPLETED,
                        module="attack_surface",
                        data=attack_surface_summary(results["attack_surface"]),
                    )
                )
            except Exception as e:
                logger.exception("attack_surface module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR,
                        module="attack_surface",
                        message=str(e),
                    )
                )

        if "threat" in enabled:
            emails = results.get("org", {}).get("whois", {}).get("emails")
            await emit(ScanEvent(type=EventType.MODULE_STARTED, module="threat"))
            try:
                async with ThreatIntel(api_manager) as threat_intel:
                    results["threat"] = await threat_intel.gather_intelligence(
                        domain, emails, depth
                    )
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_COMPLETED,
                        module="threat",
                        data=threat_summary(results["threat"]),
                    )
                )
            except Exception as e:
                logger.exception("threat module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR, module="threat", message=str(e)
                    )
                )

        if "typosquat" in enabled:
            await emit(ScanEvent(type=EventType.MODULE_STARTED, module="typosquat"))
            try:
                async with TyposquatDetector() as typosquat:
                    results["typosquat"] = await typosquat.detect(domain, depth)
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_COMPLETED,
                        module="typosquat",
                        data=typosquat_summary(results["typosquat"]),
                    )
                )
            except Exception as e:
                logger.exception("typosquat module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR,
                        module="typosquat",
                        message=str(e),
                    )
                )

        if "news" in enabled:
            await emit(ScanEvent(type=EventType.MODULE_STARTED, module="news"))
            try:
                try:
                    async with NewsMonitor() as news:
                        results["news"] = await news.monitor(domain, 30)
                except ImportError as e:
                    logger.warning(f"news module unavailable: {e}")
                    results["news"] = {
                        "error": str(e),
                        "articles": [],
                        "total_articles": 0,
                    }
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_COMPLETED,
                        module="news",
                        data=news_summary(results["news"]),
                    )
                )
            except Exception as e:
                logger.exception("news module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR, module="news", message=str(e)
                    )
                )

        await finalize_scan(results, domain, depth, modules, emit)
    except Exception as e:
        logger.exception("scan failed")
        await emit(ScanEvent(type=EventType.SCAN_FAILED, message=str(e)))

    return results
