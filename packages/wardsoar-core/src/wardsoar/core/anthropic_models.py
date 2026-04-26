"""Discover the list of Claude models available on the operator's account.

Hits the Anthropic public ``/v1/models`` endpoint, returns the
sorted list of model IDs. Used by the setup wizard's analyzer page
so the operator never has to pick from a hand-maintained dropdown
that drifts out of date the moment Anthropic ships a new model.

The function is **best-effort**: any failure (no API key, network
down, rate-limit, schema change) returns ``None`` and the wizard
falls back to its compiled-in default list. We prefer a fresh list
when we can get one but never block on it.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger("ward_soar.anthropic_models")

#: Anthropic public REST endpoint that lists every model the supplied
#: API key can call. Override via ``WARDSOAR_ANTHROPIC_MODELS_URL``
#: for tests pointing at a local fixture.
ANTHROPIC_MODELS_URL: str = "https://api.anthropic.com/v1/models"

#: Date stamp of the Anthropic API contract we target. Bump when
#: Anthropic publishes a breaking schema change.
ANTHROPIC_API_VERSION: str = "2023-06-01"

#: Timeout for the model-list call. Short — the wizard runs this on
#: the UI thread when the operator clicks Next, and a stale dropdown
#: is better than a frozen window.
_FETCH_TIMEOUT_S: float = 5.0


def fetch_available_models(
    api_key: str,
    *,
    url: Optional[str] = None,
    timeout_s: float = _FETCH_TIMEOUT_S,
) -> Optional[list[str]]:
    """Return the list of Claude model IDs available to ``api_key``.

    Synchronous on purpose — the setup wizard calls this from the
    Qt UI thread when the operator advances to the analyzer page,
    and a 5 s blocking call is acceptable when it spares the
    operator from picking outdated model IDs by hand.

    Args:
        api_key: The Anthropic API key. An empty string short-
            circuits to ``None`` without hitting the network.
        url: Override of :data:`ANTHROPIC_MODELS_URL` — useful for
            unit tests pointing at a fixture.
        timeout_s: HTTP timeout for the fetch.

    Returns:
        List of model IDs sorted from newest to oldest as Anthropic
        returns them, or ``None`` when the call cannot be completed.
        ``None`` always means "fall back to the hardcoded default" —
        never raises.
    """
    if not api_key:
        return None
    target = url or ANTHROPIC_MODELS_URL
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_API_VERSION,
    }
    try:
        response = httpx.get(target, headers=headers, timeout=timeout_s)
    except (httpx.HTTPError, OSError) as exc:
        logger.info(
            "fetch_available_models: call failed (%s) — falling back to "
            "the wizard's compiled-in defaults.",
            exc,
        )
        return None
    if response.status_code != 200:
        logger.info(
            "fetch_available_models: HTTP %s from Anthropic (%s) — falling back.",
            response.status_code,
            response.text[:200],
        )
        return None
    try:
        payload = response.json()
    except ValueError:
        logger.info("fetch_available_models: response was not JSON — falling back.")
        return None

    raw_data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(raw_data, list):
        logger.info(
            "fetch_available_models: unexpected response shape (no 'data' list) " "— falling back."
        )
        return None

    ids: list[str] = []
    for entry in raw_data:
        if not isinstance(entry, dict):
            continue
        model_id = entry.get("id")
        if isinstance(model_id, str) and model_id:
            ids.append(model_id)

    if not ids:
        logger.info("fetch_available_models: API returned zero model IDs — falling back.")
        return None
    return ids
