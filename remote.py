"""HTTP transport for the CLI; uploads are streamed from an open file."""

import json
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


class RemoteClient:
    def __init__(self, endpoint):
        parts = urlsplit(endpoint)
        if (
            parts.scheme not in ("http", "https")
            or not parts.netloc
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "endpoint must be an HTTP(S) base URL without a query or fragment"
            )
        self.endpoint = endpoint.rstrip("/")

    def request(self, route, params, body=None, size=None):
        headers = {"Accept": "application/json"}
        if body is not None:
            headers.update(
                {"Content-Type": "application/json", "Content-Length": str(size)}
            )
        request = Request(
            self.endpoint + route + "?" + urlencode(params), data=body, headers=headers
        )
        try:
            with urlopen(request, timeout=300) as response:
                return json.load(response)
        except HTTPError as exc:
            try:
                detail = json.load(exc).get("error", exc.reason)
            except (ValueError, AttributeError):
                detail = exc.reason
            finally:
                exc.close()
            raise ValueError(f"API returned HTTP {exc.code}: {detail}") from exc
        except HTTPException as exc:
            raise ValueError(f"invalid API HTTP response: {exc}") from exc
        except URLError as exc:
            raise ValueError(f"cannot reach API: {exc.reason}") from exc

    def ingest(self, path):
        with path.open("rb") as stream:
            return self.request(
                "/ingest",
                {"source": str(path.resolve()), "filename": path.name},
                body=stream,
                size=path.stat().st_size,
            )

    def query(self, component=None, version=None, license_value=None):
        params = {
            key: value
            for key, value in (
                ("component", component),
                ("version", version),
                ("license", license_value),
            )
            if value is not None
        }
        return self.request("/query", params)

    def list_components(self):
        return self.request("/components", {})

    def list_licenses(self):
        return self.request("/licenses", {})
