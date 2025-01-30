import os
import re
import json

import jwt
import dotenv
import requests
from gunicorn.config import Config
from gunicorn.glogging import Logger
from django.http import HttpResponse

from .secret import Secret
from .services import Service


def verify_auth_token(token: str, verify: bool = True):
    return jwt.decode(
        token,
        Secret.get_service_key(service=Service.AUTH),
        algorithms=["RS256"],
        verify=verify
    )


def health_check(req):
    return HttpResponse()


class Monitoring:
    def __init__(self):
        self.prep()

    def prep(self, team=None):
        if team:
            api_key = os.getenv(f"OPSGENIE_{team}_API_KEY")
        else:
            api_key = os.getenv("OPSGENIE_CHATS_API_KEY")

        self.api_url = os.getenv("OPSGENIE_API_URL")
        self.headers = {"Content-Type": "application/json", "Authorization": f"GenieKey {api_key}"}

    def alert(self, message, description=None, priority="P3", team=None):
        """
        Sends an alert to Opsgenie.

        Args:
            message (str): The alert message.
            description (str): Additional details about the alert.
            priority (str): Alert priority (e.g., P1, P2, P3, P4, P5).
        Returns:
            dict: API response.
        """

        if not self.api_url:
            self.prep(team)

        if not self.api_url:
            return {"success": False, "error": "OPSGENIE_API_URL is not set."}

        data = {"message": message, "priority": priority, "description": description, "responders": []}

        if team:
            data["responders"].append({"name": team, "type": "team"})

        else:
            data["responders"].append({"name": "chats", "type": "team"})

        response = requests.post(self.api_url, json=data, headers=self.headers)
        if response.ok:
            return {"success": True, "response": response.json()}

        return {"success": False, "error": response.json()}


class Logger(Logger):
    def __init__(self, cfg):
        dotenv.load_dotenv()
        self.monitoring = Monitoring()
        super(Logger, self).__init__(cfg)

    def d(self, message):
        return self.debug(msg=message)

    def e(self, message, service=None, description="Error"):
        self.error(f"{message}: {description}")
        self.monitoring.alert(message=message, priority="P1", description=description, team=service)
        return self.error(msg=f"{message}: {description}")

    def i(self, message):
        return self.info(msg=message)

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
