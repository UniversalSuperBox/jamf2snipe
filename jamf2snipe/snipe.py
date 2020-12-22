"""Abstractions for Snipe-IT"""

import logging
from time import sleep

import requests


class Snipe:
    """Abstracts a limited subset of Snipe-IT API calls

    :param base_url:
        Full URL (with protocol) to the Snipe-IT instance's root. For example,
        ``https://my-instance.example.com:8443``

    :param api_key: An API key which is valid to use the Snipe-IT API
    """

    def __init__(self, base_url, api_key):
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": "Bearer {}".format(api_key),
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self._session.hooks["response"] = self.request_handler
        self.base_url = base_url
        self.api_count = 0
        self._user_cache_impl = {}
        self._asset_serial_cache_impl = {}

    def request_handler(self, req, *args, **kwargs):  # pylint: disable=unused-argument
        """Handles rate limiting for the Snipe-IT server."""
        self.api_count += 1

        message_sent_already = False
        while True:
            try:
                resp_json = req.json()
            except ValueError:
                return req

            error_msg = resp_json.get("messages", "")

            if error_msg == 429 or error_msg == "429":
                if not message_sent_already:
                    logging.warning(message_sent_already)
                    logging.warning(
                        "We're being rate-limited by Snipe-IT. I'll hold off on requests for a few seconds."
                    )
                    message_sent_already = True
                sleep(3)
                re_req = req.request
                # We'll end up recursing this function if we don't set hooks
                # manually
                re_req.hooks = {"response": None}
                req = self._session.send(re_req)
            else:
                break

        return req

    def check_connection(self):
        """Ensures that my connection settings are correct.

        Attempts to contact the Snipe-IT API and raises an exception if it
        fails. If no exception was raised, it is probably safe to continue
        using this Snipe object instance.

        If the connection is successful, pre-populates the asset and user
        caches.

        This may raise any of the exceptions found in `requests.exceptions`_.

        :raises AuthorizationIncorrect:
            Our API key is incorrect.

        :returns: True in case of success, raises in any other case

        .. _requests.exceptions: https://requests.readthedocs.io/en/master/_modules/requests/exceptions/
        """

        req = self._session.get(self.base_url + "/api/v1/users", params={"limit": 1})
        if req.status_code == 200:
            # Pre-populate our caches
            self._user_cache  # pylint: disable=pointless-statement
            self._asset_serial_cache  # pylint: disable=pointless-statement

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

    def get_asset_by_serial(self, serial):
        """Looks up an asset by its serial number in Snipe-IT.

        Snipe-IT does not enforce uniqueness of the serial number, so it may
        return more than one asset for the search.

        :returns:
            If a single match is found, a dict of the matched Asset object is
            returned.

            If no match is found, the string ``"NoMatch"`` is returned.

            If more than one match is found, the string ``"MultiMatch"`` is
            returned.

            If any error occurs during the request, the string ``"ERROR"`` is
            returned.

        :param serial: Serial number to look up in Snipe-IT.
        """
        asset = self._asset_serial_cache.get(serial, None)
        if asset is not None:
            return asset

        api_url = "{}/api/v1/hardware/byserial/{}".format(self.base_url, serial)
        response = self._session.get(api_url)
        if response.status_code == 200:
            jsonresponse = response.json()
            # Check to make sure there's actually a result
            if jsonresponse["total"] == 1:
                return jsonresponse["rows"][0]
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

    @property
    def _user_cache(self):
        """Holds a cache of users by their username from Snipe-IT.

        Snipe-IT's API rate limiting is just 120 requests/minute. A lot of our
        operations on the API are simply looking up users, so if we can cache
        a list of users we'll greatly reduce our load on the API.

        This property detects whether a cache is currently held and creates
        the cache if not.

        The cache is a dictionary of {"<username>": {User}} values.
        """

        if not self._user_cache_impl:
            logging.debug("Creating Snipe-IT user cache.")
            self._user_cache_impl = {}
            cache = self.get_users()
            for user in cache:
                username = user["username"]
                self._user_cache_impl[username] = user
            logging.debug("Finished creating snipe-IT user cache.")

        return self._user_cache_impl

    @property
    def _asset_serial_cache(self):
        """Holds a cache of assets by their serial number from Snipe-IT.

        See the discussion in _user_cache for why this is needed.

        The cache is a dictionary of {"<serial number>": {Asset}} values.
        """

        if not self._asset_serial_cache_impl:
            logging.debug("Creating Snipe-IT asset cache.")
            self._asset_serial_cache_impl = {}
            cache = self._get_paginated_endpoint("/api/v1/hardware")
            for asset in cache:
                serial_number = asset["serial"]
                if self._asset_serial_cache_impl.get(serial_number, None) is not None:
                    raise MultipleAssetsForSerial(
                        "Multiple assets with the serial number {} were found.".format(
                            serial_number
                        )
                    )
                self._asset_serial_cache_impl[serial_number] = asset
            logging.debug("Finished creating Snipe-IT asset cache.")
        return self._asset_serial_cache_impl

    def _invalidate_asset_serial_cache_entry(self, serial_number):
        """Marks an asset in the asset serial cache as invalid.

        This prevents future attempts to use the asset from using the old
        cached version.

        Should be called whenever an asset is updated, checked in, checked
        out...

        :param serial_number: Serial number of the asset to invalidate
        """

        if self._asset_serial_cache_impl:
            logging.debug("Invalidating cache for %s", serial_number)
            try:
                del self._asset_serial_cache_impl[serial_number]
            except KeyError:
                # This item wasn't in the cache anyway, no worries.
                pass

    def get_user(self, username, fuzzy_search=False):
        """Get the dict object for a User given their username.

        :param username: Username to search Snipe-IT for.

        :param fuzzy_search:
            If false, the algorithm will only attempt to find users by an
            exact match on username. If true, will try to use Snipe-IT's fuzzy
            search with the username after an exact match fails.

        :returns: dict object of a User from Snipe-IT.
        """
        cached_user = self._user_cache.get(username, None)
        if cached_user is not None:
            return cached_user

        user_url = "{}/api/v1/users".format(self.base_url)
        payload = {"username": username, "limit": 1, "sort": "username", "order": "asc"}
        logging.debug("The payload for the snipe user search is: %s", payload)
        response = self._session.get(user_url, json=payload)
        try:
            return response.json()["rows"][0]
        except (KeyError, IndexError) as exact_search_error:
            if fuzzy_search:
                logging.debug(
                    "Didn't find a user for that search, re-attempting with fuzzy: %s",
                    payload,
                )
                payload = {
                    "search": username,
                    "limit": 1,
                    "sort": "username",
                    "order": "asc",
                }
                response = self._session.get(user_url, json=payload)
                try:
                    return response.json()["rows"][0]
                except (KeyError, IndexError) as fuzzy_search_error:
                    raise UserNotFound(
                        "Unable to find user {} with username or fuzzy search.".format(
                            username
                        )
                    ) from fuzzy_search_error
            raise UserNotFound(
                "Unable to find user {} by username.".format(username)
            ) from exact_search_error

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

            serial_number = jsonresponse["payload"]["serial"]
            self._invalidate_asset_serial_cache_entry(serial_number)

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

    def checkin_asset(self, asset_serial_number):
        """Checks in a single asset in Snipe-IT, removing its assignee.

        :param asset_serial_number:
            Serial number of the asset to check in.

        :returns:
            The string ``"CheckedOut"`` if the checkin was successful, the
            ``requests.Response`` object returned by the request if the
            checkin was not successful.
        """
        asset_id = self.get_asset_by_serial(asset_serial_number)["id"]
        api_url = "{}/api/v1/hardware/{}/checkin".format(self.base_url, asset_id)
        payload = {"note": "checked in by script from Jamf"}
        logging.debug("The payload for the snipe checkin is: %s", payload)
        response = self._session.post(api_url, json=payload)
        logging.debug("The response from Snipe IT is: %s", response.json())
        if response.status_code == 200:
            logging.debug("Got back status code: 200 - %s", response.content)
            self._invalidate_asset_serial_cache_entry(asset_serial_number)
            return "CheckedOut"
        return response

    def checkout_asset(
        self,
        user_id,
        asset_serial_number,
    ):
        """Checks out a single asset in Snipe-IT to the specified user.

        It is the caller's responsibility to provide the currently checked-out
        user as the ``checked_out_user`` argument.

        :param user_id: ID of the Snipe-IT user to check this asset out to.

        :param asset_serial_number:
            Serial number of the asset to check out.

        :returns:
            ``"CheckedOut"`` if the asset was checked out successfully.

            The ``requests.Response`` object returned by the checkout request
            if it was not successful.
        """
        logging.debug(
            "Asset %s is being checked out to %s", user_id, asset_serial_number
        )
        if not user_id:
            raise ValueError("User not specified in call to checkout_asset")

        asset = self.get_asset_by_serial(asset_serial_number)
        current_user = asset["assigned_to"]
        if current_user:
            current_user_id = current_user["id"]
        else:
            current_user_id = None

        if current_user_id == user_id:
            logging.debug("Asset is already checked out to desired user.")
            return "CheckedOut"

        logging.info(
            "Checking in %s from %s to check it out to %s",
            asset_serial_number,
            current_user_id,
            user_id,
        )
        self.checkin_asset(asset_serial_number)

        api_url = "{}/api/v1/hardware/{}/checkout".format(
            self.base_url, asset_serial_number
        )
        logging.info("Checking out %s to %s", asset_serial_number, user_id)
        payload = {
            "checkout_to_type": "user",
            "assigned_user": user_id,
            "note": "Assignment made automatically, via script from Jamf.",
        }
        logging.debug("The payload for the snipe checkout is: %s", payload)
        response = self._session.post(api_url, json=payload)
        logging.debug("The response from Snipe IT is: %s", response.text)
        if response.status_code == 200:
            logging.debug("Got back status code: 200 - %s", response.text)
            self._invalidate_asset_serial_cache_entry(asset_serial_number)
            return "CheckedOut"
        logging.error(
            "Asset checkout failed for asset %s with error %s",
            asset_serial_number,
            response.text,
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


class UserNotFound(SnipeItError):
    """The requested user was not found."""


class AssetNotFound(SnipeItError):
    """The requested asset was not found."""


class MultipleAssetsForSerial(SnipeItError):
    """More than one asset was found for a given serial number."""
