"""Abstractions for Jamf"""

import logging
from datetime import datetime, timezone
from time import sleep

import requests
from requests.auth import HTTPBasicAuth


class Jamf:
    """Abstracts a limited subset of Jamf API calls

    :param base_url:
        Full URL (with protocol) to the Jamf instance's root. For example,
        ``https://my-instance.example.com:8443``

    :param username: A username which is valid to use the Jamf API

    :param password: Password matching the provided username.
    """

    def __init__(self, base_url, username, password):
        self._session = requests.Session()
        self._session.hooks["response"].append(self.request_handler)
        self._session.headers.update({"Accept": "application/json"})
        self._username = username
        self._password = password
        self._session.auth = HTTPBasicAuth(self._username, self._password)
        self.base_url = base_url
        self.api_count = 0
        self.first_call = None

    def check_connection(self):
        """
        Determines if the given URL and credentials are correct by connecting
        to the Jamf server.

        :raises AuthorizationIncorrect:
            The given API credentials were not correct, or the given user does
            not have access to the mobiledevices endpoint.

        :returns:
            True if the connection succeeded, raises an error in any other
            case.
        """
        mobile_resp = self._session.get(
            "{0}/JSSResource/mobiledevices/-1".format(self.base_url)
        )
        computer_resp = self._session.get(
            "{0}/JSSResource/computers/-1".format(self.base_url)
        )
        # ID -1 should never exist, but just in case it does, handle a 200 OK too.
        # Either response means we've authenticated successfully.
        if (
            mobile_resp.status_code == 404
            or computer_resp.status_code == 404
            or mobile_resp.status_code == 200
            or computer_resp.status_code == 200
        ):
            return True
        if mobile_resp.status_code == 401 or computer_resp.status_code == 401:
            raise AuthorizationIncorrect(
                "Jamf API credentials incorrect or the given user does not have access to the mobiledevices endpoint."
            )
        logging.error(
            "An unknown error occurred while checking the Jamf connection. Is the URL correct?"
        )
        mobile_resp.raise_for_status()
        computer_resp.raise_for_status()
        logging.error(
            "An unknown error occurred while checking the Jamf connection and Requests did not raise an exception for it."
        )
        raise JamfError()

    def request_handler(
        self, r, *args, **kwargs
    ):  # pylint: disable=unused-argument,invalid-name
        """Handles rate limiting and accounting for the JAMF server."""
        if self.first_call is None:
            self.first_call = datetime.now(tz=timezone.utc)
        self.api_count += 1
        if r.status_code != 200 and b"policies.ratelimit.QuotaViolation" in r.content:
            # This case should only occur with JAMF's developer portal
            logging.warning(
                "JAMFPro Ratelimit exceeded - error code %s. Pausing for 75 seconds.",
                r.status_code,
            )
            sleep(75)
            logging.info("Finished waiting. Retrying lookup...")
            newresponse = self._session.send(r.request)
            return newresponse
        return r

    def get_computers(self):
        """Retrieves a list of all computers from the JAMF instance."""
        api_url = "{0}/JSSResource/computers".format(self.base_url)
        logging.debug(
            "Calling for JAMF computers against: %s\n The username, passwords, and headers for this GET requestcan be found near the beginning of the output.",
            api_url,
        )
        response = self._session.get(api_url)
        if response.status_code == 200:
            logging.debug("Got back a valid 200 response code.")
            return response.json()
        logging.error(
            "Received an invalid status code when trying to retreive JAMF Device list:%s - %s",
            response.status_code,
            response.content,
        )
        logging.debug("Returning a null value for the function.")
        return None

    def get_mobile_devices(self):
        """Retrieves a list of all mobile devices from the JAMF instance."""
        api_url = "{0}/JSSResource/mobiledevices".format(self.base_url)
        logging.debug(
            "Calling for JAMF mobiles against: %s\n The username, passwords, and headers for this GET requestcan be found near the beginning of the output.",
            api_url,
        )
        response = self._session.get(api_url)
        if response.status_code == 200:
            logging.debug("Got back a valid 200 response code.")
            return response.json()
        logging.error(
            "Received an invalid status code when trying to retreive JAMF Device list:%s - %s",
            response.status_code,
            response.content,
        )
        logging.debug("Returning a null value for the function.")
        return None

    def get_computer(self, jamf_id):
        """Retrieves a single computer from the JAMF instance by ID."""
        api_url = "{}/JSSResource/computers/id/{}".format(self.base_url, jamf_id)
        response = self._session.get(api_url)
        if response.status_code == 200:
            logging.debug("Got back a valid 200 response code.")
            jsonresponse = response.json()
            logging.debug("Returning: %s", jsonresponse["computer"])
            return jsonresponse["computer"]
        logging.error(
            "JAMFPro responded with error code:%s when we tried to look up id: %s",
            response,
            jamf_id,
        )
        logging.debug("Returning a null value for the function.")
        return None

    def get_mobile_device(self, jamf_id):
        """Retrieves a single mobile device from the JAMF instance by ID.

        :param jamf_id: JAMF instance's unique ID value identifying this mobile
            device.

        :param session:
            requests.Session object to use for this request. This session must have
            all headers needed for the request, including authorization headers.
        """
        api_url = "{}/JSSResource/mobiledevices/id/{}".format(self.base_url, jamf_id)
        response = self._session.get(api_url)
        if response.status_code == 200:
            logging.debug("Got back a valid 200 response code.")
            jsonresponse = response.json()
            logging.debug("Returning: %s", jsonresponse["mobile_device"])
            return jsonresponse["mobile_device"]
        logging.error(
            "JAMFPro responded with error code:%s when we tried to look up id: %s",
            response,
            jamf_id,
        )
        logging.debug("Returning a null value for the function.")
        return None

    def update_computer_asset_tag(self, jamf_id, asset_tag):
        """Updates the asset tag field on a single computer in JAMF.

        :param jamf_id:
            JAMF instance's unique ID value identifying this computer.

        :param asset_tag:
            The new value for the asset tag field for this computer in the
            JAMF instance.
        """
        api_url = "{}/JSSResource/computers/id/{}".format(self.base_url, jamf_id)
        payload = """<?xml version="1.0" encoding="UTF-8"?><computer><general><id>{}</id><asset_tag>{}</asset_tag></general></computer>""".format(
            jamf_id, asset_tag
        )
        logging.debug(
            "Making Get request against: %s\nPayload for the PUT request is: %s\nThe username, password, and headers can be found near the beginning of the output.",
            api_url,
            payload,
        )
        response = self._session.put(api_url, data=payload)
        if response.status_code == 201:
            logging.debug("Got a 201 response. Returning: True")
            return True
        if response.status_code == 200:
            logging.debug(
                "Got a 200 response code. Returning the response: %s", response
            )
            return response.json()
        logging.error(
            "Got back an error response code:%s - %s",
            response.status_code,
            response.content,
        )
        return None

    def update_mobile_device_asset_tag(self, jamf_id, asset_tag):
        """Updates the asset tag field on a single mobile device in JAMF.

        :param jamf_id:
            JAMF instance's unique ID value identifying this mobile device.

        :param asset_tag:
            The new value for the asset tag field for this mobile device in
            the JAMF instance.
        """
        api_url = "{}/JSSResource/mobiledevices/id/{}".format(self.base_url, jamf_id)
        payload = """<?xml version="1.0" encoding="UTF-8"?><mobile_device><general><id>{}</id><asset_tag>{}</asset_tag></general></mobile_device>""".format(
            jamf_id, asset_tag
        )
        logging.debug(
            "Making Get request against: %s\nPayload for the PUT request is: %s\nThe username, password, and headers can be found near the beginning of the output.",
            api_url,
            payload,
        )
        response = self._session.put(api_url, data=payload)
        if response.status_code == 201:
            logging.debug("Got a 201 response. Returning: True")
            return True
        if response.status_code == 200:
            logging.debug(
                "Got a 200 response code. Returning the response: %s", response
            )
            return response.json()
        logging.error(
            "Got back an error response code:%s - %s",
            response.status_code,
            response.content,
        )
        return None


class JamfError(Exception):
    """Thrown on general failures when contacting the Jamf API."""


class AuthorizationIncorrect(JamfError):
    """Thrown when Jamf rejects our username and password"""
