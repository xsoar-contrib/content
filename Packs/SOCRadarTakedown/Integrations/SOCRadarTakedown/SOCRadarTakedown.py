import urllib3
import traceback
import re
from typing import Any, Dict, List, Optional, Union
from json.decoder import JSONDecodeError

# Import XSOAR common functions
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
INTEGRATION_CONTEXT_NAME = "SOCRadarTakedown"
MESSAGES = {
    "BAD_REQUEST_ERROR": "An error occurred while fetching the data.",
    "AUTHORIZATION_ERROR": "Authorization Error: make sure API Key is correctly set.",
    "RATE_LIMIT_EXCEED_ERROR": "Rate limit has been exceeded. Please make sure your API key's rate limit is adequate.",
    "SUCCESS": "Request submitted successfully",
    "FAILED": "Request submission failed"
}

""" CLIENT CLASS """


class Client:
    """
    Client class to interact with the SOCRadar Takedown API
    """

    def __init__(self, base_url: str, api_key: str, company_id: str, verify: bool, proxy: bool):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.company_id = company_id
        self.headers = {
            "API-KEY": self.api_key,
            "Content-Type": "application/json"
        }
        self.verify = verify
        self.proxy = proxy

    def _http_request(self, method: str, url_suffix: str, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Generic HTTP request method with proper error handling"""
        full_url = f"{self.base_url}{url_suffix}"

        try:
            response = requests.request(
                method=method,
                url=full_url,
                headers=self.headers,
                json=json_data,
                verify=self.verify,
                proxies=handle_proxy() if self.proxy else None
            )

            # Handle different HTTP status codes
            if response.status_code == 401:
                raise DemistoException(MESSAGES["AUTHORIZATION_ERROR"])
            elif response.status_code == 429:
                raise DemistoException(MESSAGES["RATE_LIMIT_EXCEED_ERROR"])
            elif response.status_code >= 500:
                raise DemistoException(f"Server Error: {response.status_code} - {response.text}")
            elif response.status_code >= 400:
                raise DemistoException(f"Client Error: {response.status_code} - {response.text}")

            try:
                return response.json()
            except JSONDecodeError:
                return {"status_code": response.status_code, "text": response.text}

        except requests.exceptions.Timeout:
            raise DemistoException("Request timeout occurred")
        except requests.exceptions.ConnectionError:
            raise DemistoException("Connection error occurred")
        except requests.exceptions.RequestException as e:
            raise DemistoException(f"Request failed: {str(e)}")

    def test_connection(self) -> Dict[str, Any]:
        """Tests API connectivity and authentication"""
        url_suffix = f"/get/company/{self.company_id}/takedown/requests"
        return self._http_request("GET", url_suffix)

    def submit_takedown_request(self, entity: str, request_type: str, abuse_type: str,
                                notes: str = "", send_alarm: bool = True, email: str = "") -> Dict[str, Any]:
        """Submit takedown request to SOCRadar API"""
        url_suffix = f"/add/company/{self.company_id}/takedown/request"
        data = {
            "abuse_type": abuse_type,
            "entity": entity,
            "type": request_type,
            "notes": notes,
            "send_alarm": send_alarm,
            "email": email
        }

        return self._http_request("POST", url_suffix, data)


""" HELPER FUNCTIONS """


class Validator:
    @staticmethod
    def validate_domain(domain_to_validate: str) -> bool:
        """Validate domain format"""
        if not isinstance(domain_to_validate, str) or len(domain_to_validate) > 255:
            return False
        if domain_to_validate.endswith("."):
            domain_to_validate = domain_to_validate[:-1]
        domain_regex = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(domain_regex.match(x) for x in domain_to_validate.split("."))

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return email_pattern.match(email) is not None


def get_client_from_params() -> Client:
    """Initialize client from demisto params"""
    params = demisto.params()

    api_key = params.get("apikey", {}).get("password", "") if isinstance(params.get("apikey"), dict) else params.get("apikey", "")
    company_id = params.get("company_id", "").strip()
    base_url = params.get("url", SOCRADAR_API_ENDPOINT).strip()
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if not api_key:
        raise ValueError("API Key is required")
    if not company_id:
        raise ValueError("Company ID is required")

    return Client(
        base_url=base_url,
        api_key=api_key,
        company_id=company_id,
        verify=verify_certificate,
        proxy=proxy
    )


def create_takedown_command_result(entity: str, entity_type: str, abuse_type: str,
                                   notes: str, send_alarm: bool, raw_response: Dict,
                                   context_prefix: str, key_field: str) -> CommandResults:
    """Generic function to create CommandResults for takedown requests"""

    is_success = raw_response.get('is_success', False) or raw_response.get('success', False)
    status = MESSAGES["SUCCESS"] if is_success else MESSAGES["FAILED"]

    # Create readable output
    readable_output = f"### {entity_type} Takedown Request\n"
    readable_output += f"**{key_field}**: {entity}\n"
    readable_output += f"**Status**: {status}\n"
    readable_output += f"**Abuse Type**: {abuse_type}\n"

    if raw_response.get("message"):
        readable_output += f"**Message**: {raw_response.get('message')}\n"

    if notes:
        readable_output += f"**Notes**: {notes}\n"

    # Create context output
    outputs = {
        key_field: entity,
        "AbuseType": abuse_type,
        "Status": status,
        "Message": raw_response.get("message", ""),
        "SendAlarm": send_alarm,
        "Notes": notes,
        "RequestId": raw_response.get("request_id") or raw_response.get("id"),
        "Timestamp": raw_response.get("timestamp") or raw_response.get("created_at")
    }

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.{context_prefix}",
        outputs_key_field=key_field,
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response
    )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        client.test_connection()
        return "ok"
    except Exception as e:
        demisto.error(f"Test module failed: {str(e)}")
        return f"Test failed: {str(e)}"


def submit_phishing_domain_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for a phishing domain"""
    args = demisto.args()
    domain = args.get("domain", "").strip()
    abuse_type = args.get("abuse_type", "potential_phishing")
    domain_type = args.get("type", "phishing_domain")
    notes = args.get("notes", "")
    send_alarm = argToBoolean(args.get("send_alarm", True))
    email = args.get("email", "").strip()

    # Validation
    if not domain:
        raise ValueError("Domain is required")
    if not Validator.validate_domain(domain):
        raise ValueError(f'Domain "{domain}" is not valid')
    if email and not Validator.validate_email(email):
        raise ValueError(f'Email "{email}" is not valid')

    # Submit request
    raw_response = client.submit_takedown_request(
        entity=domain,
        request_type=domain_type,
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        email=email
    )

    return create_takedown_command_result(
        entity=domain,
        entity_type="Phishing Domain",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        raw_response=raw_response,
        context_prefix="PhishingDomain",
        key_field="Domain"
    )


def submit_social_media_impersonation_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for social media impersonation"""
    args = demisto.args()
    url_link = args.get("url", "").strip()
    abuse_type = args.get("abuse_type", "impersonating_accounts")
    notes = args.get("notes", "")
    send_alarm = argToBoolean(args.get("send_alarm", True))
    email = args.get("email", "").strip()

    # Validation
    if not url_link:
        raise ValueError("URL is required")
    if not Validator.validate_url(url_link):
        raise ValueError(f'URL "{url_link}" is not valid')
    if email and not Validator.validate_email(email):
        raise ValueError(f'Email "{email}" is not valid')

    # Submit request
    raw_response = client.submit_takedown_request(
        entity=url_link,
        request_type="impersonating_accounts",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        email=email
    )

    return create_takedown_command_result(
        entity=url_link,
        entity_type="Social Media Impersonation",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        raw_response=raw_response,
        context_prefix="SocialMediaImpersonation",
        key_field="URL"
    )


def submit_source_code_leak_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for leaked source code"""
    args = demisto.args()
    url_link = args.get("url", "").strip()
    abuse_type = args.get("abuse_type", "source_code_leak")
    notes = args.get("notes", "")
    send_alarm = argToBoolean(args.get("send_alarm", True))
    email = args.get("email", "").strip()

    # Validation
    if not url_link:
        raise ValueError("URL is required")
    if not Validator.validate_url(url_link):
        raise ValueError(f'URL "{url_link}" is not valid')
    if email and not Validator.validate_email(email):
        raise ValueError(f'Email "{email}" is not valid')

    # Submit request
    raw_response = client.submit_takedown_request(
        entity=url_link,
        request_type="source_code_leak",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        email=email
    )

    return create_takedown_command_result(
        entity=url_link,
        entity_type="Source Code Leak",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        raw_response=raw_response,
        context_prefix="SourceCodeLeak",
        key_field="URL"
    )


def submit_rogue_app_takedown_command(client: Client) -> CommandResults:
    """Submits a takedown request for a rogue mobile app"""
    args = demisto.args()
    app_info = args.get("app_info", "").strip()
    abuse_type = args.get("abuse_type", "rogue_mobile_app")
    notes = args.get("notes", "")
    send_alarm = argToBoolean(args.get("send_alarm", True))
    email = args.get("email", "").strip()

    # Validation
    if not app_info:
        raise ValueError("App info is required")
    if email and not Validator.validate_email(email):
        raise ValueError(f'Email "{email}" is not valid')

    # Submit request
    raw_response = client.submit_takedown_request(
        entity=app_info,
        request_type="rogue_mobile_app",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        email=email
    )

    return create_takedown_command_result(
        entity=app_info,
        entity_type="Rogue App",
        abuse_type=abuse_type,
        notes=notes,
        send_alarm=send_alarm,
        raw_response=raw_response,
        context_prefix="RogueApp",
        key_field="AppInfo"
    )


""" MAIN FUNCTION """


def main():
    """Main function, parses params and runs command functions"""
    try:
        demisto.debug(f"Command being called: {demisto.command()}")

        if demisto.command() == "test-module":
            client = get_client_from_params()
            result = test_module(client)
            return_results(result)

        else:
            client = get_client_from_params()

            commands = {
                "socradar-submit-phishing-domain": submit_phishing_domain_takedown_command,
                "socradar-submit-social-media-impersonation": submit_social_media_impersonation_takedown_command,
                "socradar-submit-source-code-leak": submit_source_code_leak_takedown_command,
                "socradar-submit-rogue-app": submit_rogue_app_takedown_command,
            }

            command = demisto.command()
            if command in commands:
                return_results(commands[command](client))
            else:
                raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
