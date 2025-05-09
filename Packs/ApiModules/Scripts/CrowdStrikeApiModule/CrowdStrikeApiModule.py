from datetime import timedelta

import dateparser
from CommonServerPython import *

from CommonServerUserPython import *

TOKEN_LIFE_TIME = timedelta(minutes=28)


class CrowdStrikeClient(BaseClient):
    def __init__(self, params):
        """
        CrowdStrike Client class that implements OAuth2 authentication.
        Args:
            params: Demisto params
        """
        credentials = params.get("credentials", {})
        self._client_id = credentials.get("identifier")
        self._client_secret = credentials.get("password")
        super().__init__(
            base_url=params.get("server_url", "https://api.crowdstrike.com/"),
            verify=not params.get("insecure", False),
            ok_codes=(),
            proxy=params.get("proxy", False),
        )  # type: ignore[misc]
        self.timeout = float(params.get("timeout", "10"))
        self._token = self._get_token()
        self._headers = {"Authorization": "bearer " + self._token}

    @staticmethod
    def _error_handler(res: requests.Response):
        """
        Converting the errors of the API to a string, in case there are no error, return an empty string
        :param res: the request's response
        :return: None
        """
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}\n"
        try:
            # Try to parse json error response
            error_entry = res.json()
            errors = error_entry.get("errors", [])
            err_msg += "\n".join(
                f"{error.get('code')}: {error.get('message')}"
                for error in errors  # pylint: disable=no-member
            )
            if "Failed to issue access token - Not Authorized" in err_msg:
                err_msg = err_msg.replace("Failed to issue access token - Not Authorized", "Client Secret is invalid.")
            elif "Failed to generate access token for clientID" in err_msg:
                err_msg = err_msg.replace("Failed to generate access token for clientID=", "Client ID (")
                if err_msg.endswith("."):
                    err_msg = err_msg[:-1]
                err_msg += ") is invalid."
            raise DemistoException(err_msg)
        except ValueError:
            err_msg += f"\n{res.text}"
            raise DemistoException(err_msg)

    def http_request(
        self,
        method,
        url_suffix,
        full_url=None,
        headers=None,
        json_data=None,
        params=None,
        data=None,
        files=None,
        timeout=10,
        ok_codes=None,
        return_empty_response=False,
        auth=None,
        resp_type="json",
    ):
        """A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type full_url: ``str``
        :param full_url:
            Bypasses the use of self._base_url + url_suffix. This is useful if you need to
            make a request to an address outside of the scope of the integration
            API.

        :type headers: ``dict``
        :param headers: Headers to send in the request. If None, will use self._headers.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :type data: ``dict``
        :param data: The data to send in a 'POST' request.

        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.

        :type files: ``dict``
        :param files: The file data to send in a 'POST' request.

        :type timeout: ``float`` or ``tuple``
        :param timeout:
            The amount of time (in seconds) that a request will wait for a client to
            establish a connection to a remote machine before a timeout occurs.
            can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).

        :type ok_codes: ``tuple``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204). If you specify
            "None", will use self._ok_codes.

        :type return_empty_response: ``bool``
        :param return_empty_response: Indicates whether we are expecting empty response (like 204) or not.

        :return: Depends on the resp_type parameter
        :rtype: ``dict`` or ``str`` or ``requests.Response``
        """

        req_timeout = timeout
        if self.timeout:
            req_timeout = self.timeout

        return super()._http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            json_data=json_data,
            params=params,
            data=data,
            files=files,
            timeout=req_timeout,
            ok_codes=ok_codes,
            return_empty_response=return_empty_response,
            auth=auth,
            error_handler=self._error_handler,
            resp_type=resp_type,
        )

    def _get_token(self, force_gen_new_token=False):
        """
        Retrieves the token from the server if it's expired and updates the global HEADERS to include it

        :param force_gen_new_token: If set to True will generate a new token regardless of time passed

        :rtype: ``str``
        :return: Token
        """
        now = datetime.now()
        ctx = get_integration_context()
        if not ctx or not ctx.get("generation_time", force_gen_new_token):
            # new token is needed
            auth_token = self._generate_token()
        else:
            generation_time = dateparser.parse(ctx.get("generation_time"))
            if generation_time and now:
                time_passed = now - generation_time
            else:
                time_passed = TOKEN_LIFE_TIME
            if time_passed < TOKEN_LIFE_TIME:
                # token hasn't expired
                return ctx.get("auth_token")
            else:
                # token expired
                auth_token = self._generate_token()

        ctx.update({"auth_token": auth_token, "generation_time": now.strftime("%Y-%m-%dT%H:%M:%S")})
        set_integration_context(ctx)
        return auth_token

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {"client_id": self._client_id, "client_secret": self._client_secret}
        token_res = self.http_request("POST", "/oauth2/token", data=body, auth=(self._client_id, self._client_secret))
        return token_res.get("access_token")

    def check_quota_status(self) -> dict:
        """Checking the status of the quota
        :return: http response
        """
        url_suffix = "/falconx/entities/submissions/v1?ids="
        return self.http_request("GET", url_suffix)
