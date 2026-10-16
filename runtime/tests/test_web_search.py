from __future__ import annotations

from types import SimpleNamespace

from strix.tools.web_search import tool as web_search_tool


class _Response:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def _settings(**overrides):
    integrations = {
        "searxng_url": "http://searxng.test:8080",
        "searxng_timeout": 7,
        "searxng_max_results": 1,
        "perplexity_api_key": None,
    }
    integrations.update(overrides)
    return SimpleNamespace(integrations=SimpleNamespace(**integrations))


def test_web_search_uses_searxng(monkeypatch) -> None:
    captured = {}

    def fake_get(url, *, params, headers, timeout):
        captured.update(url=url, params=params, headers=headers, timeout=timeout)
        return _Response(
            {
                "results": [
                    {
                        "title": "FastAPI docs",
                        "url": "https://fastapi.tiangolo.com/",
                        "content": "FastAPI content",
                        "engine": "duckduckgo",
                        "score": 1.0,
                    },
                    {"title": "Skipped"},
                ]
            }
        )

    monkeypatch.setattr(web_search_tool, "load_settings", lambda: _settings())
    monkeypatch.setattr(web_search_tool.requests, "get", fake_get)

    result = web_search_tool._do_search("fastapi security")

    assert result["success"] is True
    assert result["provider"] == "searxng"
    assert result["results"] == [
        {
            "title": "FastAPI docs",
            "url": "https://fastapi.tiangolo.com/",
            "content": "FastAPI content",
            "engine": "duckduckgo",
            "score": 1.0,
        }
    ]
    assert captured["url"] == "http://searxng.test:8080/search"
    assert captured["params"]["format"] == "json"
    assert captured["timeout"] == 7


def test_web_search_falls_back_to_perplexity(monkeypatch) -> None:
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(("searxng", args, kwargs))
        raise web_search_tool.requests.exceptions.ConnectionError("offline")

    def fake_perplexity(query, api_key):
        calls.append(("perplexity", query, api_key))
        return {"success": True, "provider": "perplexity", "query": query, "content": "answer"}

    monkeypatch.setattr(
        web_search_tool,
        "load_settings",
        lambda: _settings(perplexity_api_key="pk-test"),
    )
    monkeypatch.setattr(web_search_tool.requests, "get", fake_get)
    monkeypatch.setattr(web_search_tool, "_do_perplexity_search", fake_perplexity)

    result = web_search_tool._do_search("openssl cve")

    assert result["provider"] == "perplexity"
    assert [call[0] for call in calls] == ["searxng", "perplexity"]


def test_web_search_reports_unconfigured() -> None:
    result = web_search_tool._do_search("   ")

    assert result == {"success": False, "error": "Query cannot be empty"}
