import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import emails  # type: ignore
import jwt
from jinja2 import Template
from jwt.exceptions import InvalidTokenError

from app.core import security
from app.core.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class EmailData:
    html_content: str
    subject: str


def render_email_template(*, template_name: str, context: dict[str, Any]) -> str:
    template_str = (
        Path(__file__).parent / "email-templates" / "build" / template_name
    ).read_text()
    html_content = Template(template_str).render(context)
    return html_content


def send_email(
    *,
    email_to: str,
    subject: str = "",
    html_content: str = "",
) -> None:
    assert settings.emails_enabled, "no provided configuration for email variables"
    message = emails.Message(
        subject=subject,
        html=html_content,
        mail_from=(settings.EMAILS_FROM_NAME, settings.EMAILS_FROM_EMAIL),
    )
    smtp_options = {"host": settings.SMTP_HOST, "port": settings.SMTP_PORT}
    if settings.SMTP_TLS:
        smtp_options["tls"] = True
    elif settings.SMTP_SSL:
        smtp_options["ssl"] = True
    if settings.SMTP_USER:
        smtp_options["user"] = settings.SMTP_USER
    if settings.SMTP_PASSWORD:
        smtp_options["password"] = settings.SMTP_PASSWORD
    response = message.send(to=email_to, smtp=smtp_options)
    logger.info(f"send email result: {response}")


def generate_test_email(email_to: str) -> EmailData:
    project_name = settings.PROJECT_NAME
    subject = f"{project_name} - Test email"
    html_content = render_email_template(
        template_name="test_email.html",
        context={"project_name": settings.PROJECT_NAME, "email": email_to},
    )
    return EmailData(html_content=html_content, subject=subject)


def generate_reset_password_email(email_to: str, email: str, token: str) -> EmailData:
    project_name = settings.PROJECT_NAME
    subject = f"{project_name} - Password recovery for user {email}"
    link = f"{settings.FRONTEND_HOST}/reset-password?token={token}"
    html_content = render_email_template(
        template_name="reset_password.html",
        context={
            "project_name": settings.PROJECT_NAME,
            "username": email,
            "email": email_to,
            "valid_hours": settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS,
            "link": link,
        },
    )
    return EmailData(html_content=html_content, subject=subject)


def generate_new_account_email(
    email_to: str, username: str, password: str
) -> EmailData:
    project_name = settings.PROJECT_NAME
    subject = f"{project_name} - New account for user {username}"
    html_content = render_email_template(
        template_name="new_account.html",
        context={
            "project_name": settings.PROJECT_NAME,
            "username": username,
            "password": password,
            "email": email_to,
            "link": settings.FRONTEND_HOST,
        },
    )
    return EmailData(html_content=html_content, subject=subject)


def generate_password_reset_token(email: str) -> str:
    delta = timedelta(hours=settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS)
    now = datetime.now(timezone.utc)
    expires = now + delta
    exp = expires.timestamp()
    encoded_jwt = jwt.encode(
        {"exp": exp, "nbf": now, "sub": email},
        settings.SECRET_KEY,
        algorithm=security.ALGORITHM,
    )
    return encoded_jwt


def verify_password_reset_token(token: str) -> str | None:
    try:
        decoded_token = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        return str(decoded_token["sub"])
    except InvalidTokenError:
        return None


# MikroTik Router API Client
import httpx
from typing import Dict, List


class MikroTikAPIError(Exception):
    """Custom exception for MikroTik API errors."""

    pass


def get_mikrotik_url(router_ip: str, port: int = 80) -> str:
    """
    Build the base URL for MikroTik API.
    port: Port number (default 80 for HTTP, use 443 for HTTPS)
    """
    # Use HTTPS for port 443, HTTP for everything else
    protocol = "https" if port == 443 else "http"
    return f"{protocol}://{router_ip}:{port}"


async def test_mikrotik_connection(
    router_ip: str, username: str, password: str, port: int = 80
) -> Dict[str, Any]:
    """
    Test connection to MikroTik router and fetch system resource info.
    Returns router details if successful.
    Raises MikroTikAPIError if connection fails.
    """
    base_url = get_mikrotik_url(router_ip, port)
    url = f"{base_url}/rest/system/resource"

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            response = await client.get(
                url, auth=httpx.BasicAuth(username, password)
            )

            if response.status_code == 401:
                raise MikroTikAPIError("Authentication failed: Invalid credentials")

            if response.status_code != 200:
                raise MikroTikAPIError(
                    f"Failed to connect: HTTP {response.status_code}"
                )

            data = response.json()
            return data

    except httpx.ConnectError:
        raise MikroTikAPIError(f"Connection failed: Unable to reach {router_ip}")
    except httpx.TimeoutException:
        raise MikroTikAPIError(f"Connection timeout: {router_ip} did not respond")
    except Exception as e:
        raise MikroTikAPIError(f"Unexpected error: {str(e)}")


async def get_mikrotik_serial_number(
    router_ip: str, username: str, password: str, port: int = 80
) -> str:
    """
    Get the serial number from MikroTik router.
    Returns serial number from /rest/system/routerboard.
    Raises MikroTikAPIError if connection fails.
    """
    base_url = get_mikrotik_url(router_ip, port)
    url = f"{base_url}/rest/system/routerboard"

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            response = await client.get(
                url, auth=httpx.BasicAuth(username, password)
            )

            if response.status_code == 401:
                raise MikroTikAPIError("Authentication failed: Invalid credentials")

            if response.status_code != 200:
                raise MikroTikAPIError(
                    f"Failed to get routerboard info: HTTP {response.status_code}"
                )

            data = response.json()
            serial = data.get("serial-number")

            if not serial:
                raise MikroTikAPIError("Serial number not found in routerboard info")

            return serial

    except httpx.ConnectError:
        raise MikroTikAPIError(f"Connection failed: Unable to reach {router_ip}")
    except httpx.TimeoutException:
        raise MikroTikAPIError(f"Connection timeout: {router_ip} did not respond")
    except Exception as e:
        raise MikroTikAPIError(f"Unexpected error getting serial number: {str(e)}")


async def discover_mikrotik_neighbors(
    router_ip: str, username: str, password: str, port: int = 80
) -> List[Dict[str, Any]]:
    """
    Discover neighbor devices from MikroTik router.
    Returns list of neighbor device information.
    Raises MikroTikAPIError if discovery fails.
    """
    base_url = get_mikrotik_url(router_ip, port)
    url = f"{base_url}/rest/ip/neighbor"

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            response = await client.get(
                url, auth=httpx.BasicAuth(username, password)
            )

            if response.status_code == 401:
                raise MikroTikAPIError("Authentication failed: Invalid credentials")

            if response.status_code != 200:
                raise MikroTikAPIError(
                    f"Failed to discover neighbors: HTTP {response.status_code}"
                )

            neighbors = response.json()
            return neighbors if isinstance(neighbors, list) else []

    except httpx.ConnectError:
        raise MikroTikAPIError(f"Connection failed: Unable to reach {router_ip}")
    except httpx.TimeoutException:
        raise MikroTikAPIError(f"Connection timeout: {router_ip} did not respond")
    except Exception as e:
        raise MikroTikAPIError(f"Unexpected error during discovery: {str(e)}")
