"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. We grab a guest token by
``session.exec()``-ing curl from inside the container, then construct
a host-side :class:`caido_sdk_client.Client` against the runtime's
exposed-port URL for all subsequent SDK calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client


logger = logging.getLogger(__name__)


def _parse_inject_headers() -> list[tuple[str, str]]:
    """Parse STRIX_INJECT_HEADERS env var into (name, value) pairs.

    Format: comma-separated "Header-Name: value" entries.
    """
    raw = os.environ.get("STRIX_INJECT_HEADERS", "").strip()
    if not raw:
        return []
    results = []
    for entry in raw.split(","):
        entry = entry.strip()
        if ":" not in entry:
            continue
        name, _, value = entry.partition(":")
        results.append((name.strip(), value.strip()))
    return results


async def _setup_inject_headers(client: "Client", headers: list[tuple[str, str]]) -> None:
    """Create a Caido tamper rule collection that injects the given headers into every request."""
    if not headers:
        return

    # Create a dedicated collection for injected headers
    coll_result = await client.graphql.mutation(
        "mutation CreateColl($input: CreateTamperRuleCollectionInput!) { "
        "createTamperRuleCollection(input: $input) { collection { id } } }",
        variables={"input": {"name": "Injected Headers"}},
    )
    coll_id = (
        coll_result.get("createTamperRuleCollection", {})
        .get("collection", {})
        .get("id")
    )
    if not coll_id:
        logger.warning("Failed to create tamper rule collection; skipping header injection")
        return

    for name, value in headers:
        rule_result = await client.graphql.mutation(
            "mutation CreateRule($input: CreateTamperRuleInput!) { "
            "createTamperRule(input: $input) { rule { id } } }",
            variables={
                "input": {
                    "collectionId": coll_id,
                    "name": f"Inject {name}",
                    "section": {
                        "requestHeader": {
                            "operation": {
                                "add": {
                                    "matcher": {"name": name},
                                    "replacer": {"term": {"term": value}},
                                }
                            }
                        }
                    },
                    # INTERCEPT = proxy traffic; empty list means no source = rule never fires
                    "sources": ["INTERCEPT"],
                }
            },
        )
        rule_id = (
            rule_result.get("createTamperRule", {})
            .get("rule", {})
            .get("id")
        )
        if rule_id:
            # Rules are disabled by default; must be explicitly toggled on
            await client.graphql.mutation(
                "mutation ToggleRule($id: ID!) { toggleTamperRule(id: $id, enabled: true) { rule { id } } }",
                variables={"id": rule_id},
            )
        logger.info("Tamper rule created and enabled: always add request header %s", name)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    attempts: int = 10,
) -> str:
    """``session.exec`` curl to fetch a guest token; retry until ready.

    Caido's GraphQL listener may not be up the instant the container
    starts. The retry loop also doubles as the Caido readiness probe —
    no separate TCP healthcheck needed.
    """
    last_err: str | None = None
    for i in range(1, attempts + 1):
        result = await session.exec(
            "curl",
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            _LOGIN_AS_GUEST_BODY,
            f"{container_url}/graphql",
            timeout=15,
        )
        if result.ok():
            try:
                payload = json.loads(result.stdout)
                token = (
                    payload.get("data", {})
                    .get("loginAsGuest", {})
                    .get("token", {})
                    .get("accessToken")
                )
                if token:
                    return str(token)
                last_err = f"loginAsGuest returned no token: {payload}"
            except json.JSONDecodeError as exc:
                last_err = f"unparseable response: {exc}: {result.stdout!r}"
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:200]
            last_err = f"curl exit {result.exit_code}: {stderr}"
        logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
        await asyncio.sleep(min(2.0 * i, 8.0))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
) -> Client:
    """Connect to the in-container Caido sidecar and select a fresh project."""
    # The Caido SDK (and its generated GraphQL schema) is slow to import and is
    # only needed once a sandbox is actually being bootstrapped, so it is
    # imported here rather than at module scope.
    from caido_sdk_client import Client, TokenAuthOptions
    from caido_sdk_client.types import CreateProjectOptions

    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    access_token = await _login_as_guest(session, container_url=container_url)

    client = Client(host_url, auth=TokenAuthOptions(token=access_token))
    try:
        # connect() is inside the guard as well: a cancellation there (scan
        # teardown while the bootstrap is still in flight) would otherwise
        # leave the half-connected transport behind.
        await client.connect()
        project = await client.project.create(
            CreateProjectOptions(name="sandbox", temporary=True),
        )
        await client.project.select(project.id)
        inject_headers = _parse_inject_headers()
        if inject_headers:
            try:
                await _setup_inject_headers(client, inject_headers)
            except Exception:
                logger.warning("Header injection setup failed; continuing without it", exc_info=True)
        # Caido starts with intercept mode ON by default — requests are held for
        # manual review and CONNECT tunnels never complete. Disable request,
        # response, and WebSocket interception so traffic flows through automatically.
        # NOTE: pauseIntercept only pauses the queue; it does NOT set enabled=false,
        # so new requests are still captured. setInterceptOptions is the correct call.
        try:
            await client.graphql.mutation(
                "mutation SetOpts($input: InterceptOptionsInput!) {"
                "  setInterceptOptions(input: $input) {"
                "    options { request { enabled } response { enabled } }"
                "  }"
                "}",
                variables={
                    "input": {
                        "request": {"enabled": False},
                        "response": {"enabled": False},
                        "streamWs": {"enabled": False},
                    }
                },
            )
            logger.info("Caido intercept disabled (request/response/ws enabled=false)")
        except Exception:
            logger.warning("Failed to disable Caido intercept mode; tunnels may hang", exc_info=True)
    except BaseException:
        # The client never reaches the session bundle if connect or project
        # setup fails, so close it here to avoid leaking the transport.
        with contextlib.suppress(Exception):
            await client.aclose()
        raise
    logger.info("Caido project selected: %s", project.id)
    return client
