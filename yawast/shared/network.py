import secrets
from http import cookiejar
from typing import List, Dict, Union, Tuple
from urllib.parse import urlparse, urljoin
from urllib.parse import urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.models import Response, Request, PreparedRequest
from urllib3 import Retry

from yawast._version import get_version
from yawast.reporting import reporter
from yawast.shared import output

YAWAST_UA = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"YAWAST/{get_version()}/PY Chrome/74.0.3729.169 Safari/537.36"
)

SERVICE_UA = f"YAWAST/{get_version()}/PY"


# class to block setting cookies from server responses
class _BlockCookiesSet(cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


_requester = requests.Session()


def init(proxy: str, cookie: str) -> None:
    global _requester

    _requester.cookies.set_policy(_BlockCookiesSet())
    _requester.mount(
        "http://",
        HTTPAdapter(
            max_retries=Retry(total=5, read=5, connect=5, backoff_factor=0.3),
            pool_maxsize=50,
        ),
    )
    _requester.mount(
        "https://",
        HTTPAdapter(
            max_retries=Retry(total=5, read=5, connect=5, backoff_factor=0.3),
            pool_maxsize=50,
        ),
    )

    if proxy is not None and len(proxy) > 0:
        # we have a proxy, set it
        if not proxy.startswith("http"):
            proxy = f"http://{proxy}"

        proxies = {"http": proxy, "https": proxy}

        _requester.proxies.update(proxies)

    if cookie is not None and len(cookie) > 0:
        name = cookie.split("=")[0]
        val = cookie.split("=")[1]
        c = requests.cookies.create_cookie(name=name, value=val)

        _requester.cookies.set_cookie(c)


def http_head(url, allow_redirects=True, timeout=15) -> Response:
    global _requester

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"User-Agent": YAWAST_UA}
    res = _requester.head(
        url,
        headers=headers,
        verify=False,
        allow_redirects=allow_redirects,
        timeout=timeout,
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_options(url, timeout=15) -> Response:
    global _requester

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"User-Agent": YAWAST_UA}
    res = _requester.options(url, headers=headers, verify=False, timeout=timeout)

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_get(
    url: str, allow_redirects=True, additional_headers: Union[None, Dict] = None
) -> Response:

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": YAWAST_UA}

    if additional_headers is not None:
        headers = {**headers, **additional_headers}

    res = _requester.get(
        url, headers=headers, verify=False, allow_redirects=allow_redirects
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_put(
    url: str,
    data: str,
    allow_redirects=True,
    additional_headers: Union[None, Dict] = None,
) -> Response:

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": YAWAST_UA}

    if additional_headers is not None:
        headers = {**headers, **additional_headers}

    res = _requester.put(
        url, data=data, headers=headers, verify=False, allow_redirects=allow_redirects
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_custom(
    verb: str, url: str, additional_headers: Union[None, Dict] = None
) -> Response:

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": YAWAST_UA}

    if additional_headers is not None:
        headers = {**headers, **additional_headers}

    res = _requester.request(verb, url, headers=headers, verify=False)

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_json(url, allow_redirects=True) -> Tuple[Dict, int]:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": SERVICE_UA}

    res = _requester.get(
        url, headers=headers, verify=False, allow_redirects=allow_redirects
    )
    return res.json(), res.status_code


def http_build_raw_response(res: Response) -> str:
    lines = []

    if res.raw.version == 11:
        res_line = f"HTTP/1.1 {res.raw.status} {res.raw.reason}"
    elif res.raw.version == 10:
        res_line = f"HTTP/1.0 {res.raw.status} {res.raw.reason}"
    else:
        raise ValueError(f"Invalid HTTP version ({res.raw.version})")

    if res_line != "":
        lines.append(res_line)

    for header in res.headers:
        lines.append(f"{header}: {res.headers[header]}")

    try:
        txt = res.text

        if txt != "":
            lines.append("")
            lines.append("")

            for line in txt.splitlines():
                lines.append(line)
    except Exception:
        output.debug_exception()

    return "\r\n".join(lines)


def http_build_raw_request(req: Union[Request, PreparedRequest]) -> str:
    headers = "\n".join(f"{k}: {v}" for k, v in req.headers.items())

    body = ""
    if req.body is not None:
        body = req.body

    return f"{req.method} {req.url}\n{headers}\n\n{body}"


def check_404_response(url: str) -> Tuple[bool, Response, bool, Response]:
    rnd = secrets.token_hex(12)
    file_url = urljoin(url, f"{rnd}.html")
    path_url = urljoin(url, f"{rnd}/")

    file_res = http_get(file_url, False)
    path_res = http_get(path_url, False)

    return file_res.status_code == 404, file_res, path_res.status_code == 404, path_res


def check_ssl_redirect(url):
    parsed = urlparse(url)

    if parsed.scheme == "https":
        return url

    req = http_head(url, False)

    # make sure we received a redirect response
    if req.status_code >= 300 & req.status_code < 400:
        location = req.headers.get("location")

        if location is None:
            return url

        try:
            parsed_location = urlparse(location)

            # this is a special case to handle servers that redirect to a path, and then to HTTPS
            if parsed_location.netloc == "" and parsed_location.path != "":
                parsed_location = parsed._replace(path=parsed_location.path)
                parsed_location = urlparse(
                    check_ssl_redirect(urlunparse(parsed_location))
                )

            if parsed_location.scheme == "https":
                parsed = parsed._replace(scheme=parsed_location.scheme)

                return urlunparse(parsed)
        except ValueError:
            return url
    else:
        return url


def check_www_redirect(url):
    parsed = urlparse(url)

    req = http_head(url, False)

    # make sure we received a redirect response
    if req.status_code >= 300 & req.status_code < 400:
        location = req.headers.get("location")

        if location is None:
            return url

        try:
            parsed_location = urlparse(location)

            if parsed.netloc.startswith("www") & (
                not parsed_location.netloc.startswith("www")
            ):
                parsed_location = parsed._replace(netloc=parsed_location.netloc)

                return urlunparse(parsed_location)
            elif (
                not parsed.netloc.startswith("www")
            ) & parsed_location.netloc.startswith("www"):
                parsed_location = parsed._replace(netloc=parsed_location.netloc)

                return urlunparse(parsed_location)
        except ValueError:
            return url
    else:
        return url


def check_ipv4_connection() -> str:
    prefix = "IPv4 -> Internet:"
    url = "https://ipv4.icanhazip.com/"

    res = _check_connection(url)

    reporter.register_info("ipv4", res)

    return f"{prefix} {res}"


def check_ipv6_connection() -> str:
    prefix = "IPv6 -> Internet:"
    url = "https://ipv6.icanhazip.com/"

    res = _check_connection(url)

    reporter.register_info("ipv6", res)

    return f"{prefix} {res}"


def _check_connection(url: str) -> str:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    result = "Connection Failed"

    try:
        headers = {"User-Agent": SERVICE_UA}

        res = requests.get(url, headers=headers, verify=False)

        result = res.text.strip()
    except Exception:
        output.debug_exception()

    return result
