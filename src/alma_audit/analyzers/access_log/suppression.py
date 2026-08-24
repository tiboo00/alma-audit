"""Crawler-suppression wrapper for the access_log analyzer.

Wraps the §6.1 verification chain with a never-raises safety net, so a
buggy resolver cannot crash the scan. The fail-closed contract lives in
`crawler_verify.py`; this module is the adapter the analyzer uses.
"""

from __future__ import annotations

from ...analyzers.crawler_verify import (
    CrawlerSuppression,
    Resolver,
    verify_crawler,
)


def resolve_suppression(
    resolver: Resolver,
    ip: str,
    user_agent: str,
) -> CrawlerSuppression:
    """Run the §6.1 chain and return the suppression decision.

    Never raises: any exception is swallowed and reported as
    `ptr_error`, keeping the caller fail-closed. The resolver itself
    is also expected to swallow network errors (the production
    `SocketResolver` does); this guard is an additional safety net
    for tests that substitute a buggy resolver.
    """
    if not ip or not user_agent:
        return CrawlerSuppression(
            applied=False, reason="no_claim", claimed=None,
            hostname=None, suffix=None,
        )
    try:
        return verify_crawler(ip, user_agent, resolver)
    except Exception:
        return CrawlerSuppression(
            applied=False, reason="ptr_error", claimed=None,
            hostname=None, suffix=None,
        )