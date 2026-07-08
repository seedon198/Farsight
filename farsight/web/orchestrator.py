"""Event-emitting scan orchestrator for the web UI.

Mirrors farsight.cli.scan.run_scan()'s module sequence and wiring
without importing or modifying that module, so the CLI path
(stabilized separately) carries zero additional risk from this code.

Deviates from run_scan() in one deliberate way: each module runs in
its own try/except, so one module failing doesn't abort the whole
scan. A live demo should degrade gracefully, not die on stage because
one network call timed out.
"""

import asyncio
from typing import Any, Awaitable, Callable, Dict, List

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


def _org_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_related_domains": result.get("total_related_domains", 0),
        "total_subdomains": result.get("total_subdomains", 0),
        "whois_found": bool(result.get("whois")),
    }


def _recon_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    port_scan = result.get("port_scan") or {}
    email_security = result.get("email_security") or {}
    return {
        "total_subdomains": result.get("total_subdomains", 0),
        "total_open_ports": port_scan.get("total_open_ports", 0),
        "spf_found": bool((email_security.get("spf") or {}).get("found")),
        "dmarc_found": bool((email_security.get("dmarc") or {}).get("found")),
    }


def _threat_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_leaks": result.get("total_leaks", 0),
        "total_dark_web": result.get("total_dark_web", 0),
        "total_credentials": result.get("total_credentials", 0),
        "total_emails_found": result.get("total_emails_found", 0),
    }


def _typosquat_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    typosquats = result.get("typosquats") or []
    return {
        "total_generated": result.get("total_generated", 0),
        "total_active": result.get("total_active", 0),
        "top_risk": typosquats[:5],
    }


def _news_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total_articles": result.get("total_articles", 0),
        "days_monitored": result.get("days_monitored", 0),
    }


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
                        data=_org_summary(results["org"]),
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
                        data=_recon_summary(results["recon"]),
                    )
                )
            except Exception as e:
                logger.exception("recon module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR, module="recon", message=str(e)
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
                        data=_threat_summary(results["threat"]),
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
                        data=_typosquat_summary(results["typosquat"]),
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
                        data=_news_summary(results["news"]),
                    )
                )
            except Exception as e:
                logger.exception("news module failed")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR, module="news", message=str(e)
                    )
                )

        report_id = None
        if results:
            writer = ReportWriter()
            completed_modules = list(results.keys())
            report_path = await asyncio.to_thread(
                writer.generate_report,
                results=results,
                target=domain,
                depth=depth,
                modules=completed_modules,
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

        await emit(
            ScanEvent(
                type=EventType.SCAN_COMPLETED,
                data={
                    "completed_modules": list(results.keys()),
                    "failed_modules": [m for m in modules if m not in results],
                    "report_id": report_id,
                },
            )
        )
    except Exception as e:
        logger.exception("scan failed")
        await emit(ScanEvent(type=EventType.SCAN_FAILED, message=str(e)))

    return results
