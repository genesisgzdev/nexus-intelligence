import re
import random
import asyncio
from urllib.parse import urljoin, urlparse, urlunsplit
from typing import Dict, Any, List
from curl_cffi.requests import AsyncSession
from bs4 import BeautifulSoup
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.core.security import SecurityValidator

SIGNATURES = {
    "frameworks": {
        "WordPress": [re.compile(r"wp-content", re.I), re.compile(r"wp-includes", re.I)],
        "Laravel": [re.compile(r"XSRF-TOKEN", re.I), re.compile(r"laravel_session", re.I)],
        "React": [re.compile(r"react-root", re.I), re.compile(r"_reactRootContainer", re.I)],
        "Vue.js": [re.compile(r"vue-app", re.I), re.compile(r"v-attr", re.I)],
    },
    "security_controls": {
        "Cloudflare": [re.compile(r"cf-ray", re.I), re.compile(r"__cfduid", re.I)],
        "Akamai": [re.compile(r"akamai-", re.I), re.compile(r"akamai_", re.I)],
        "AWS_WAF": [re.compile(r"AWSALB", re.I), re.compile(r"AWSALBCORS", re.I)],
        "ModSecurity": [re.compile(r"Mod_Security", re.I), re.compile(r"NO_CACHE", re.I)],
        "FortiWeb": [re.compile(r"FORTIWAFSID", re.I)],
    }
}

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def pinned_http_request(url: str) -> tuple[str, str]:
    """Build a request URL pinned to an address accepted by the SSRF gate."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("request target is not an allowed HTTP(S) URL")
    destination = SecurityValidator.resolve_public_addresses(parsed.hostname)[0]
    host_header = parsed.hostname
    if parsed.port is not None and parsed.port not in {80, 443}:
        host_header = f"{host_header}:{parsed.port}"
    if ":" in destination and not destination.startswith("["):
        destination = f"[{destination}]"
    pinned_netloc = destination if parsed.port is None else f"{destination}:{parsed.port}"
    return urlunsplit((parsed.scheme, pinned_netloc, parsed.path or "/", parsed.query, "")), host_header


async def pinned_http_request_async(url: str, timeout: float) -> tuple[str, str]:
    """Build a request URL without blocking the event loop on DNS."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("request target is not an allowed HTTP(S) URL")
    destination = (await SecurityValidator.resolve_public_addresses_async(parsed.hostname, timeout))[0]
    host_header = parsed.hostname
    if parsed.port is not None and parsed.port not in {80, 443}:
        host_header = f"{host_header}:{parsed.port}"
    if ":" in destination and not destination.startswith("["):
        destination = f"[{destination}]"
    pinned_netloc = destination if parsed.port is None else f"{destination}:{parsed.port}"
    return urlunsplit((parsed.scheme, pinned_netloc, parsed.path or "/", parsed.query, "")), host_header

class WebIntelligence(BaseModule):
    """
    Advanced Web Intelligence Engine.
    Performs application stack fingerprinting and security header audit.
    """
    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing application stack (Async): {self.target}")
        res: Dict[str, Any] = {
            "frameworks": [],
            "security_controls": [],
            "security_headers": {},
            "misconfigurations": []
        }
        
        try:
            async with AsyncSession(impersonate="chrome120") as s:
                current_url = f"https://{self.target}"
                r = None
                for _ in range(5):
                    pinned_url, host_header = await pinned_http_request_async(current_url, self.config.timeout)
                    r = await s.get(
                        pinned_url,
                        headers={"Host": host_header},
                        timeout=self.config.timeout,
                        verify=False,
                        allow_redirects=False,
                        stream=True,
                    )
                    if r.status_code not in {301, 302, 303, 307, 308}:
                        break
                    location = r.headers.get("Location")
                    if not location:
                        await r.aclose()
                        break
                    next_url = urljoin(current_url, location)
                    parsed = urlparse(next_url)
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                        await r.aclose()
                        raise ValueError("redirect target is not an allowed HTTP(S) host")
                    if not await SecurityValidator.is_safe_target_async(parsed.hostname, self.config.timeout):
                        await r.aclose()
                        raise ValueError("redirect target resolves to a restricted address")
                    await r.aclose()
                    current_url = next_url
                if r is None:
                    raise RuntimeError("web request did not produce a response")
                if r.status_code in {301, 302, 303, 307, 308}:
                    await r.aclose()
                    raise ValueError("redirect limit exceeded")

                res['status_code'] = r.status_code

                content_length = r.headers.get("Content-Length")
                if content_length and content_length.isdigit() and int(content_length) > MAX_RESPONSE_BYTES:
                    await r.aclose()
                    res["body_truncated"] = True
                    res["body_bytes"] = 0
                    return res

                chunks: list[bytes] = []
                total = 0
                truncated = False
                async for chunk in r.aiter_content(64 * 1024):
                    remaining = MAX_RESPONSE_BYTES - total
                    if remaining <= 0:
                        truncated = True
                        break
                    chunks.append(chunk[:remaining])
                    total += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        truncated = True
                        break
                await r.aclose()
                body_content = b"".join(chunks).decode("utf-8", errors="replace")
                res["body_truncated"] = truncated
                res["body_bytes"] = total
                
                # 1. Signature-based fingerprinting
                headers_str = str(r.headers)
                for category, sigs in SIGNATURES.items():
                    for name, patterns in sigs.items():
                        if any(p.search(body_content) or p.search(headers_str) for p in patterns):
                            res[category].append(name)

                # 2. Security Header Audit
                critical_headers = {
                    "Content-Security-Policy": "Missing CSP",
                    "Strict-Transport-Security": "Missing HSTS",
                    "X-Content-Type-Options": "Missing No-Sniff",
                    "X-Frame-Options": "Missing Clickjacking protection"
                }
                for h, alert in critical_headers.items():
                    val = r.headers.get(h)
                    if val:
                        res['security_headers'][h] = val
                    else:
                        res['misconfigurations'].append(alert)

                # 3. Detect potentially dangerous headers
                dangerous = ["Server", "X-Powered-By", "X-AspNet-Version"]
                for h in dangerous:
                    val = r.headers.get(h)
                    if val:
                        res['security_headers'][f"Information_Leak_{h}"] = val

                soup = BeautifulSoup(body_content, "lxml")
                if soup.title:
                    res['title'] = soup.title.get_text().strip()

        except Exception as e:
            self.logger.error(f"Web module failure for {self.target}: {str(e)}")
            res['error'] = str(e)

        return res
