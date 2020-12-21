"""Abstractions for Snipe-IT"""

import logging
from datetime import datetime, timezone
from time import sleep

import requests


class Snipe:
    """Abstracts a limited subset of Snipe-IT API calls

    :param base_url:
        Full URL (with protocol) to the Snipe-IT instance's root. For example,
        ``https://my-instance.example.com:8443``

    :param api_key: An API key which is valid to use the Snipe-IT API
    """

    def __init__(self, base_url, api_key, rate_limited=True):
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": "Bearer {}".format(api_key),
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self.base_url = base_url
        self.api_count = 0
        self.first_call = datetime.min
        self.rate_limited = rate_limited

    def request_handler(self, req, *args, **kwargs):  # pylint: disable=unused-argument
        """Handles rate limiting for the Snipe-IT server."""
        if self.rate_limited:
            if '"messages":429' in req.text:
                logging.warning(
                    "Despite respecting the rate limit of Snipe, we've still been limited. Trying again after sleeping for 2 seconds."
                )
                sleep(2)
                re_req = req.request
                return self._session.send(re_req)
            if self.first_call == datetime.min:
                self.first_call = datetime.now(tz=timezone.utc)
            self.api_count += 1
            time_elapsed = datetime.now(tz=timezone.utc) - self.first_call
            snipe_api_rate = self.api_count / time_elapsed.total_seconds()
            if snipe_api_rate > 1.95:
                sleep_time = 0.5 + (snipe_api_rate - 1.95)
                logging.debug(
                    "Going over snipe rate limit of 120/minute (%s/minute), sleeping for %s",
                    snipe_api_rate,
                    sleep_time,
                )
                sleep(sleep_time)
            logging.debug(
                "Made %s requests to Snipe IT in %s seconds, with a request being sent every %s seconds",
                self.api_count,
                time_elapsed,
                snipe_api_rate,
            )
        if '"messages":429' in req.text:
            logging.error(req.content)
            raise RateLimitError("Rate limit hit during request to Snipe-IT.")
        return req

    def check_connection(self):
        """Ensures that my connection settings are correct.

        Attempts to contact the Snipe-IT API and raises an exception if it
        fails. If no exception was raised, it is probably safe to continue
        using this Snipe object instance.

        This may raise any of the exceptions found in `requests.exceptions`_.

        :raises AuthorizationIncorrect:
            Our API key is incorrect.

        :returns: True in case of success, raises in any other case

        .. _requests.exceptions: https://requests.readthedocs.io/en/master/_modules/requests/exceptions/
        """

        req = self._session.get(self.base_url + "/api/v1/users", params={"limit": 1})
        if req.status_code == 200:
            return True
        if req.status_code == 401:
            raise AuthorizationIncorrect(
                "Call to /api/v1/users failed, ensure your Snipe-IT API key is correct."
            )
        logging.error(
            "An unknown error occurred while checking the Snipe-IT connection. Is the URL correct?"
        )
        req.raise_for_status()
        raise SnipeItError(
            "Snipe-IT API returned HTTP {}. {}".format(req.status_code, req.text)
        )

    def search_asset(self, serial):
        """Looks up an asset by its serial number in Snipe-IT.

        Snipe-IT does not enforce uniqueness of the serial number, so it may
        return more than one asset for the search.

        :returns:
            If a single match is found, a dict object representing the match
            is returned.

            If no match is found, the string ``"NoMatch"`` is returned.

            If more than one match is found, the string ``"MultiMatch"`` is
            returned.

            If any error occurs during the request, the string ``"ERROR"`` is
            returned.

        :param serial: Serial number to look up in Snipe-IT.
        """
        api_url = "{}/api/v1/hardware/byserial/{}".format(self.base_url, serial)
        response = self._session.get(api_url)
        if response.status_code == 200:
            jsonresponse = response.json()
            # Check to make sure there's actually a result
            if jsonresponse["total"] == 1:
                return jsonresponse
            if jsonresponse["total"] == 0:
                logging.info("No assets match %s", serial)
                return "NoMatch"
            logging.warning(
                "FOUND %s matching assets while searching for: %s",
                jsonresponse["total"],
                serial,
            )
            return "MultiMatch"
        logging.warning(
            "Snipe-IT responded with error code:%s when we tried to look up: %s",
            response.text,
            serial,
        )
        logging.debug("%s - %s", response.status_code, response.content)
        return "ERROR"

    def _get_paginated_endpoint(self, endpoint):
        """Gets all of the items found at a given paginated endpoint.

        It seems like every system implements pagination differently, Snipe-IT
        is no exception. Snipe-IT's pagination involves the server telling us
        how many items there are in total and leaving us to figure out which
        ones we need to request.

        :param endpoint:
            Endpoint to retrieve items from. For example, ``/api/v1/users``

        :returns: List of dicts representing the objects from the endpoint.
        """
        api_url = "{}/{}".format(self.base_url, endpoint)
        retrieved = 0
        total = 1  # Will be overridden later
        items = []
        while retrieved < total:
            payload = {"limit": 1000, "offset": retrieved}
            logging.debug("The payload for the snipe items GET is %s", payload)
            response = self._session.get(api_url, json=payload)
            response_json = response.json()
            this_iteration_items = response_json["rows"]
            retrieved += len(this_iteration_items)
            items.extend(this_iteration_items)

            server_total = response_json["total"]
            if total == 1 and server_total != 1:
                total = server_total
            elif server_total != total:
                raise SnipeItError(
                    "Snipe-IT's total user count changed while we were retrieving {}! Please try again.".format(
                        endpoint
                    )
                )

        return items

    def get_models(self):
        """Looks up all of the asset models in Snipe-IT.

        Returns a List of dicts representing models.
        """
        return self._get_paginated_endpoint("/api/v1/models")

    def get_users(self):
        """Get a list of all users in Snipe-IT.

        :returns: List of dicts representing users
        """
        return self._get_paginated_endpoint("/api/v1/users")

    def get_user_id(self, username, user_list, do_not_search):
        """Get a Snipe-IT user's unique identifier given their username.

        :param username: Username to search Snipe-IT for.

        :param user_list: A list of users returned by get_snipe_users.

        :param do_not_search:
            Do not try to use the Snipe-IT user search to find the requested
            username if we were completely unable to find them in user_dict.

        :returns: ``"id"`` value of the user object from Snipe-IT.
        """
        if username == "":
            return "NotFound"
        username = username.lower()
        for user in user_list:
            for value in user.values():
                if str(value).lower() == username:
                    user_id = user["id"]
                    return user_id
        if do_not_search:
            logging.debug(
                "No matches in user_list for %s, not querying the API for the next closest match since we've been told not to",
                username,
            )
            return "NotFound"
        logging.debug(
            "No matches in user_list for %s, querying the API for the next closest match",
            username,
        )
        user_id_url = "{}/api/v1/users".format(self.base_url)
        payload = {"search": username, "limit": 1, "sort": "username", "order": "asc"}
        logging.debug("The payload for the snipe user search is: %s", payload)
        response = self._session.get(user_id_url, json=payload)
        try:
            return response.json()["rows"][0]["id"]
        except (KeyError, IndexError):
            return "NotFound"

    def create_model(self, payload):
        """Creates a new model in Snipe-IT.

        :param payload:
            JSON to send directly to the models endpoint in Snipe-IT.

        :returns: The new model's unique identifier (id) value in Snipe-IT.

        :raises ValueError: Snipe-IT returned a status code other than 200 OK.
        """
        api_url = "{}/api/v1/models".format(self.base_url)
        logging.debug(
            "Calling to create new snipe model type against: %s\nThe payload for the POST request is:%s\nThe request headers can be found near the start of the output.",
            api_url,
            payload,
        )
        response = self._session.post(api_url, json=payload)
        if response.status_code == 200:
            return response.json()["payload"]["id"]
        raise ValueError(
            "Received error code {} when trying to create a new asset model in Snipe-IT. The response content is:\n{}".format(
                response.status_code, response.text
            )
        )

    def create_asset(self, payload):
        """Creates a new asset in Snipe-IT.

        :param payload:
            JSON to send directly to the models endpoint in Snipe-IT.

        :returns:
            Created asset as a dict.

        :raises AssetCreationError:
            Snipe-IT returned anything but a success.
        """
        api_url = "{}/api/v1/hardware".format(self.base_url)
        logging.debug(
            "Calling to create a new asset against: %s\nThe payload for the POST request is:%s\nThe request headers can be found near the start of the output.",
            api_url,
            payload,
        )
        response = self._session.post(api_url, json=payload)
        logging.debug(response.text)
        response_json = response.json()
        if response.status_code == 200 and response_json["status"] == "success":
            logging.debug("Got back status code: 200 - %s", response.content)
            return response_json["payload"]
        raise AssetCreationError(response.text)

    def update_asset(self, snipe_id, payload):
        """Updates an existing asset in Snipe-IT.

        :param snipe_id:
            Unique identifier of the object to update in Snipe-IT.

        :param payload:
            JSON to send directly to the models endpoint in Snipe-IT.

        :returns: True if the update was successful, False if it was not.
        """
        api_url = "{}/api/v1/hardware/{}".format(self.base_url, snipe_id)
        logging.debug("The payload for the snipe update is: %s", payload)
        response = self._session.patch(api_url, json=payload)
        # Verify that the payload updated properly.
        goodupdate = True
        if response.status_code == 200:
            logging.debug(
                "Got back status code: 200 - Checking the payload updated properly: If you error here it's because you configure the API mapping right."
            )
            jsonresponse = response.json()

            if jsonresponse["status"] != "success":
                logging.error(
                    "Unable to update ID: %s.\nSnipe-IT says: %s\nWe tried to update with payload %s",
                    snipe_id,
                    jsonresponse["messages"],
                    payload,
                )
                return False

            for key in payload:
                if jsonresponse["payload"][key] != payload[key]:
                    logging.error(
                        'Unable to update ID: %s. We failed to update the %s field with "%s"',
                        snipe_id,
                        key,
                        payload[key],
                    )
                    goodupdate = False
                else:
                    logging.info("Sucessfully updated %s with: %s", key, payload[key])
            return goodupdate
        logging.warning(
            "Whoops. Got an error status code while updating ID %s: %s - %s",
            snipe_id,
            response.status_code,
            response.content,
        )
        return False

    def checkin_asset(self, asset_id):
        """Checks in a single asset in Snipe-IT, removing its assignee.

        :param asset_id:
            Unique identifier of the object to update in Snipe-IT.

        :returns:
            The string ``"CheckedOut"`` if the checkin was successful, the
            ``requests.Response`` object returned by the request if the
            checkin was not successful.
        """
        api_url = "{}/api/v1/hardware/{}/checkin".format(self.base_url, asset_id)
        payload = {"note": "checked in by script from Jamf"}
        logging.debug("The payload for the snipe checkin is: %s", payload)
        response = self._session.post(api_url, json=payload)
        logging.debug("The response from Snipe IT is: %s", response.json())
        if response.status_code == 200:
            logging.debug("Got back status code: 200 - %s", response.content)
            return "CheckedOut"
        return response

    def checkout_asset(
        self,
        user,
        asset_id,
        user_list,
        do_not_search,
        checked_out_user=None,
        default_user=None,
    ):
        """Checks out a single asset in Snipe-IT to the specified user.

        It is the caller's responsibility to provide the currently checked-out
        user as the ``checked_out_user`` argument.

        :param user: Username of the user to check this asset out to.

        :param asset_id:
            Unique identifier of the object to update in Snipe-IT.

        :param user_list: A list of users returned by get_snipe_users.

        :param do_not_search:
            Do not try to use the Snipe-IT user search to find the requested
            username if we were completely unable to find them in user_dict.

        :param checked_out_user:
            Unique identifier (``"id"``) of the user which this asset is
            checked out to at call time, or ``"NewAsset"`` if this asset was
            just created.

        :param default_user:
            Unique identifier (``"id"``) of user to check this asset out to if
            the user specified by the ``user`` argument is not found.

        :returns:
            ``"NotFound"`` if the user with the given username does not exist.

            ``"CheckedOut"`` if the asset was checked out successfully.

            The ``requests.Response`` object returned by the checkout request
            if it was not successful.
        """
        logging.debug("Asset %s is being checked out to %s", user, asset_id)
        if user:
            user_id = self.get_user_id(user, user_list, do_not_search)
        else:
            logging.debug("No user specified, not checking out this asset")
            return "NoUserSpecified"
        if user_id == "NotFound":
            logging.info("User %s not found", user)
            if default_user is None:
                logging.debug("No default user specified, returning error value")
                return "NotFound"
            logging.debug("We have a default user ID, using that.")
            user_id = default_user
        if checked_out_user is None:
            logging.info("Not checked out, attempting to check out to %s", user)
        elif checked_out_user == "NewAsset":
            logging.info(
                "First time this asset will be checked out, checking out to %s", user
            )
        elif checked_out_user["id"] == user_id:
            logging.info("%s already checked out to user %s", asset_id, user)
            return "CheckedOut"
        logging.info("Checking in %s to check it out to %s", asset_id, user)
        self.checkin_asset(asset_id)
        api_url = "{}/api/v1/hardware/{}/checkout".format(self.base_url, asset_id)
        logging.info("Checking out %s to check it out to %s", asset_id, user)
        payload = {
            "checkout_to_type": "user",
            "assigned_user": user_id,
            "note": "Assignment made automatically, via script from Jamf.",
        }
        logging.debug("The payload for the snipe checkin is: %s", payload)
        response = self._session.post(api_url, json=payload)
        logging.debug("The response from Snipe IT is: %s", response.json())
        if response.status_code == 200:
            logging.debug("Got back status code: 200 - %s", response.content)
            return "CheckedOut"
        logging.error(
            "Asset checkout failed for asset %s with error %s", asset_id, response.text
        )
        return response

    def get_manufacturers(self):
        """Returns a list of manufacturers in snipe-it"""
        return self._get_paginated_endpoint("/api/v1/manufacturers")

    def get_apple_manufacturer(self):
        """Returns the integer ID of the "Apple" manufacturer in snipe-it.

        Raises ValueError if the "Apple" manufacturer is not found.
        """
        logging.info("Searching for the manufacturer with the name 'Apple'")
        for manufacturer in self.get_manufacturers():
            if manufacturer["name"].casefold() == "apple":
                manufacturer_id = manufacturer["id"]
                logging.info(
                    "Found the manufacturer with the name 'Apple', its ID is %i",
                    manufacturer_id,
                )
                return manufacturer_id

        raise ValueError("The Apple manufacturer was not found.")


class SnipeItError(Exception):
    """Thrown on general failures when contacting the Snipe-IT API."""


class AuthorizationIncorrect(SnipeItError):
    """Thrown when Snipe-IT rejects our API key"""


class RateLimitError(Exception):
    """Thrown when Snipe-IT returns a rate limit error that we could not handle"""


class AssetCreationError(SnipeItError):
    """Thrown when creating a Snipe-IT asset fails"""
