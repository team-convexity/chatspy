import os
import re
import json

import jwt
import dotenv
import requests
import sentry_sdk
from gunicorn.config import Config
from gunicorn.glogging import Logger
from django.http import HttpResponse

from .secret import Secret
from .services import Service

sentry_dsn = os.getenv("SENTRY_DSN")
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1")),
        profiles_sample_rate=float(os.getenv("SENTRY_PROFILES_SAMPLE_RATE", "0.1")),
        environment=os.getenv("SENTRY_ENVIRONMENT", "production"),
    )


def verify_auth_token(token: str, verify: bool = True):
    return jwt.decode(token, Secret.get_service_key(service=Service.AUTH), algorithms=["RS256"], verify=verify)


def health_check(req):
    return HttpResponse()


class Monitoring:
    """
    Monitoring class that uses Sentry for error reporting.
    This implementation is failure-safe and will never cause the application to crash.
    """

    def __init__(self):
        self.enabled = bool(os.getenv("SENTRY_DSN"))

    def alert(self, message, description=None, priority="P3", team=None):
        """
        Sends an alert/event to Sentry.

        Args:
            message (str): The alert message.
            description (str): Additional details about the alert.
            priority (str): Alert priority (P1=error, P2=warning, P3+=info).
            team (str): Team context (added as a tag).
        Returns:
            dict: Response status.
        """
        if not self.enabled:
            return {"success": False, "error": "Sentry monitoring is not enabled"}

        try:
            # map priority to Sentry level
            level_map = {
                "P1": "error",
                "P2": "warning",
            }
            level = level_map.get(priority, "info")

            with sentry_sdk.push_scope() as scope:
                if team:
                    scope.set_tag("team", team)

                scope.set_tag("priority", priority)
                if description:
                    scope.set_context("details", {"description": description})

                sentry_sdk.capture_message(message, level=level)

            return {"success": True, "provider": "sentry"}

        except Exception:
            return {"success": False, "error": "Failed to send alert"}


class Logger(Logger):
    def __init__(self, cfg):
        dotenv.load_dotenv()
        self.monitoring = Monitoring()
        super(Logger, self).__init__(cfg)

    def d(self, message, description=None):
        msg = f"{message}: {description}" if description else message
        return self.debug(msg=msg)

    def e(self, message, service=None, description="Error"):
        self.error(f"{message}: {description}")
        self.monitoring.alert(message=message, priority="P1", description=description, team=service)
        return self.error(msg=f"{message}: {description}")

    def i(self, message, description=None):
        msg = f"{message}: {description}" if description else message
        return self.info(msg=msg)

    def w(self, message, service=None, description="Warning"):
        self.warning(f"{message}: {description}")
        self.monitoring.alert(message=message, priority="P2", description=description, team=service)
        return self.warning(msg=f"{message}: {description}")

    @staticmethod
    def get_logger():
        return Logger(Config())


logger = Logger.get_logger()


async def clean_inner_event_data(string: str):
    if isinstance(string, list) or isinstance(string, dict):
        return string

    return re.sub(
        r'\\+"|""null""|""|: ,|"\\"|\\\\',  # Handles multiple issues in one pattern
        lambda match: {
            '\\"': "",  # Remove escaped quotes
            '""null""': "null",  # Replace ""null"" with null
            '""': '"',  # Replace double double-quotes
            ": ,": ": null,",  # Fix missing values
            "\\\\": "",  # Remove backslashes
        }.get(match.group(0), ""),  # Default fallback for unmatched cases
        string,
    )


def clean_outer_event_data(data: dict):
    """
    cleans the data by removing extra escape characters and nested quotes.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            data[key] = clean_outer_event_data(value)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            data[idx] = clean_outer_event_data(item)

    elif isinstance(data, str):
        data = data.replace('\\"', '"').strip('"')
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            pass  # if it's not a valid json, leave it as a string

    return data


def is_production():
    return True if "production" in os.getenv("DJANGO_SETTINGS_MODULE") else False


def is_development():
    return True if "development" in os.getenv("DJANGO_SETTINGS_MODULE") else False


def get_ip_location(ip_address: str) -> dict | None:
    """
    returns the country code and name for a given IP address using the GeoIP2 database.
    """

    from geoip2 import database, errors  # type: ignore

    geoip_db_path = "./_database/geoliteii_country.mmdb"

    try:
        # load the db
        reader = database.Reader(geoip_db_path)

        response = reader.country(ip_address)
        country_code = response.country.iso_code
        country_name = response.country.name
        return {"country_code": country_code, "country_name": country_name}

    except errors.AddressNotFoundError:
        return None

    except Exception as e:
        logger.error(f"Cannot retrieve ip location for {ip_address}:: {str(e)}")
        return None


def get_currency_from_country_code(country_code, cache_client) -> str | None:
    cache_key = f"currency_{country_code}"

    currency_code = cache_client.get(cache_key)
    if currency_code:
        return currency_code

    url = f"https://restcountries.com/v3.1/alpha/{country_code}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data:
            currencies = data[0].get("currencies", {})
            if currencies:
                currency_code = list(currencies.keys())[0]

                cache_client.set(cache_key, currency_code, timeout=None)
                return currency_code

    except requests.exceptions.RequestException as e:
        logger.error(f"error fetching currency for {country_code}: {e}")

    except (KeyError, IndexError, ValueError) as e:
        logger.error(f"error parsing api response for {country_code}: {e}")

    return None
