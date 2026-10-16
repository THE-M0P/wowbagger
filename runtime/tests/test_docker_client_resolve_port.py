"""StrixDockerSandboxSession._resolve_exposed_port() under network_mode=host.

A host-mode container shares the host's network namespace directly, so Docker
never populates NetworkSettings.Networks["host"] with an IPAddress. The
generic (non-host) resolution path treats a missing IP as the container not
being on the network and raises ExposedPortUnavailableError — which broke
every run started with STRIX_DOCKER_SANDBOX_NETWORK=host, since no exposed
port could ever resolve.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from agents.sandbox.errors import ExposedPortUnavailableError

from strix.runtime.docker_client import StrixDockerSandboxSession


def _session(sandbox_network: str, networks: dict) -> StrixDockerSandboxSession:
    session = StrixDockerSandboxSession.__new__(StrixDockerSandboxSession)
    session.sandbox_network = sandbox_network
    session._container = SimpleNamespace(
        reload=MagicMock(),
        attrs={"NetworkSettings": {"Networks": networks}},
    )
    session.state = SimpleNamespace(exposed_ports=())
    return session


@pytest.mark.asyncio
async def test_host_network_resolves_without_ip_lookup():
    """host network mode: port passes through to 127.0.0.1 without needing
    an IP from NetworkSettings (Docker never gives the "host" network one)."""
    session = _session("host", networks={"host": {}})

    endpoint = await session._resolve_exposed_port(48080)

    assert endpoint.host == "127.0.0.1"
    assert endpoint.port == 48080
    session._container.reload.assert_not_called()


@pytest.mark.asyncio
async def test_non_host_network_still_requires_ip():
    """Non-host networks are unaffected: a missing IP still raises."""
    session = _session("custom-net", networks={"custom-net": {}})

    with pytest.raises(ExposedPortUnavailableError):
        await session._resolve_exposed_port(48080)

    session._container.reload.assert_called_once()


@pytest.mark.asyncio
async def test_non_host_network_resolves_with_ip():
    session = _session("custom-net", networks={"custom-net": {"IPAddress": "172.18.0.5"}})

    endpoint = await session._resolve_exposed_port(48080)

    assert endpoint.host == "172.18.0.5"
    assert endpoint.port == 48080
