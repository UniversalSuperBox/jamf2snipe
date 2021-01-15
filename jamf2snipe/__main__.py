#!/bin/python3
"""
jamf2snipe - Inventory Import

ABOUT:
    This program is designed to import inventory information from a
    JAMFPro into snipe-it using api calls. For more information
    about both of these products, please visit their respecitive
    websites:
        https://jamf.com
        https://snipeitapp.com

LICENSE:
    MIT

CONFIGURATION:
    These settings are commonly found in the settings.conf file.

    This setting sets the Snipe Asset status when creating a new asset. By
    default it's set to 4 (Pending).
    defaultStatus = 4

    You can associate snipe hardware keys in the [api-mapping] section to JAMF
    key so it associates the jamf values into snipe. The default example
    associates information that exists by default in both Snipe and JAMF. The
    Key value is the exact name of the snipe key name. Value1 is the "Subset"
    (JAMF's wording not mine) name, and the Value2 is the JAMF key name. Note
    that MAC Address are a custom value in SNIPE by default and you can use it
    as an example.

    [api-mapping]
        name = general name
        _snipeit_mac_address_1 = general mac_address
        _snipeit_custom_name_1234567890 = subset jamf_key

    A list of valid subsets can be found in the 'validsubset' variable
"""
validsubset = [
    "general",
    "location",
    "purchasing",
    "peripherals",
    "hardware",
    "certificates",
    "software",
    "extension_attributes",
    "groups_accounts",
    "iphones",
    "configuration_profiles",
]


import argparse
import configparser
import logging
import sys
import time
import concurrent.futures
import secrets
import string

import requests

import snipe
import jamf

MANAGED_NOTES = "This record is managed by jamf2snipe. Please only edit this asset's information in Jamf. Your changes in Snipe-IT will be overwritten."

# Set us up for using runtime arguments by defining them.
runtimeargs = argparse.ArgumentParser()
runtimeargs.add_argument(
    "-v",
    "--verbose",
    help="Sets the logging level to INFO and gives you a better idea of what the script is doing.",
    action="store_true",
)
runtimeargs.add_argument(
    "--dryrun",
    help="This checks your config and tries to contact both the JAMFPro and Snipe-it instances, but exits before updating or syncing any assets.",
    action="store_true",
)
runtimeargs.add_argument(
    "-d",
    "--debug",
    help="Sets logging to include additional DEBUG messages.",
    action="store_true",
)
runtimeargs.add_argument(
    "--do_not_verify_ssl",
    help="Skips SSL verification for all requests. Helpful when you use self-signed certificate.",
    action="store_true",
)
runtimeargs.add_argument(
    "-r",
    "--ratelimited",
    help="Ignored -- Was previously used to enable rate-limit handling for Snipe-IT, it is now always enabled.",
    action="store_true",
)
runtimeargs.add_argument(
    "-f",
    "--force",
    help="Updates the Snipe asset with information from Jamf every time, despite what the timestamps indicate.",
    action="store_true",
)
runtimeargs.add_argument(
    "-uns",
    "--users_no_search",
    help="Doesn't search for any users if the specified fields in Jamf and Snipe don't match. (case insensitive)",
    action="store_true",
)
runtimeargs.add_argument(
    "--create_snipe_users",
    help="Creates users in Snipe-IT if they don't exist.",
    action="store_true",
)
user_opts = runtimeargs.add_mutually_exclusive_group()
user_opts.add_argument(
    "-u",
    "--users",
    help="Checks out the item to the current user in Jamf if it's not already deployed",
    action="store_true",
)
user_opts.add_argument(
    "-uf",
    "--users_force",
    help="Checks out the item to the user specified in Jamf no matter what",
    action="store_true",
)
type_opts = runtimeargs.add_mutually_exclusive_group()
type_opts.add_argument(
    "-m",
    "--mobiles",
    help="Runs against the Jamf mobiles endpoint only.",
    action="store_true",
)
type_opts.add_argument(
    "-c",
    "--computers",
    help="Runs against the Jamf computers endpoint only.",
    action="store_true",
)
USER_ARGS = runtimeargs.parse_args()
ALLOW_FUZZY_SEARCH = not USER_ARGS.users_no_search

# Notify users they're going to get a wall of text in verbose mode.
if USER_ARGS.verbose:
    logging.basicConfig(level=logging.INFO)
elif USER_ARGS.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.WARNING)

# Notify users if we're doing a dry run.
if USER_ARGS.dryrun:
    print("Dryrun: Starting jamf2snipe with a dry run where no assets will be updated.")

# Find a valid settings.conf file.
logging.info("Searching for a valid settings.conf file.")
config = configparser.ConfigParser()
logging.debug("Checking for a settings.conf in /opt/jamf2snipe ...")
config.read("/opt/jamf2snipe/settings.conf")
if "snipe-it" not in set(config):
    logging.debug(
        "No valid config found in: /opt Checking for a settings.conf in /etc/jamf2snipe ..."
    )
    config.read("/etc/jamf2snipe/settings.conf")
if "snipe-it" not in set(config):
    logging.debug(
        "No valid config found in /etc Checking for a settings.conf in current directory ..."
    )
    config.read("settings.conf")
if "snipe-it" not in set(config):
    logging.debug("No valid config found in current folder.")
    logging.error(
        "No valid settings.conf was found. We'll need to quit while you figure out where the settings are at. You can check the README for valid locations."
    )
    raise SystemExit("Error: No valid settings.conf - Exiting.")

logging.info(
    "Great, we found a settings file. Let's get started by parsing all fo the settings."
)

# Set some Variables from the settings.conf:
# This is the address, cname, or FQDN for your JamfPro instance.
JAMF_BASE = config["jamf"]["url"]
logging.info("The configured JAMFPro base url is: %s", JAMF_BASE)
JAMF_API_USER = config["jamf"]["username"]
logging.info(
    "The configured JAMFPro username we'll be connecting with is: %s", JAMF_API_USER
)
JAMF_API_PASSWORD = config["jamf"]["password"]
logging.debug("The configured password to access the API is: %s", JAMF_API_PASSWORD)

# This is the address, cname, or FQDN for your snipe-it instance.
defaultStatus = config["snipe-it"]["defaultStatus"]
logging.info(
    "The default status we'll be setting updated computer to is: %s (I sure hope this is a number or something is probably wrong)",
    defaultStatus,
)

# TODO: Fail if defaultStatus is not an integer, assuming Snipe-IT can't accept anything but integer statuses.

### Setup Some Functions ###
SNIPE_API_COUNT = 0
FIRST_SNIPE_CALL = None


def create_user_if_not_exists(
    snipe_api,
    allow_fuzzy_search,
    real_name,
    username,
    email,
):
    """Create the given user if they don't exist.

    :param snipe_api: snipe.Snipe instance that the user will live in.

    :param allow_fuzzy_search:
        See snipe.Snipe.get_user's documentation for fuzzy_search.

    All other parameters match the Snipe-IT API. If the username is empty, the
    function returns. If first_name is not set, the function uses the username.

    Creates a random password for the user, but creates the user without the
    ability to sign in.
    """
    if not username:
        return

    try:
        first_name, last_name = real_name.split(maxsplit=1)
    except ValueError:
        first_name = real_name
        last_name = ""

    if not first_name:
        first_name = username
        last_name = ""

    try:
        snipe_api.get_user(username, fuzzy_search=allow_fuzzy_search)
    except snipe.UserNotFound:
        # The user can't log in, but we should set a very good password anyway
        logging.info("Creating new user %s", username)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = "".join(secrets.choice(alphabet) for i in range(64))
        snipe_api.create_user(
            first_name, last_name, username, password, email, activated=False
        )


def set_checked_out_user(snipe_api, asset, username, allow_fuzzy_search):
    """Tries to set the checked-out user to the specified one.

    If the given username is blank and the asset is checked out, then the asset
    will be checked in.

    :param snipe_api: snipe.Snipe instance that the asset lives in.

    :param asset: Dict representing the Snipe-IT asset's JSON.

    :param username: Username to check asset out to.

    :param allow_fuzzy_search:
        See snipe.Snipe.get_user's documentation for fuzzy_search.

    :returns: True if the checkout attempt was successful, False if it was not.
    """

    asset_serial = asset["serial"]

    if not username:
        if asset["assigned_to"] is not None:
            snipe_api.checkin_asset(asset_serial)
        return True

    try:
        target_snipe_user = snipe_api.get_user(
            username, fuzzy_search=allow_fuzzy_search
        )
        snipe_api.checkout_asset(target_snipe_user["id"], asset_serial)
        return True
    except snipe.UserNotFound:
        logging.error(
            "Could not find user %s in snipe-it, leaving item with serial number %s not checked out. Fuzzy search: %s",
            username,
            asset_serial,
            allow_fuzzy_search,
        )
    return False


def main():
    # Do some tests to see if the user has updated their settings.conf file
    settings_correct = True
    if "api-mapping" in config:
        logging.error(
            "Looks like you're using the old method for api-mapping. Please use computers-api-mapping and mobile_devices-api-mapping."
        )
        settings_correct = False
    if "user-mapping" not in config and (USER_ARGS.users or USER_ARGS.users_force):
        logging.error(
            """You've chosen to check out assets to users in some capacity using a cmdline switch, but not specified how you want to
        search Snipe IT for the users from Jamf. Make sure you have a 'user-mapping' section in your settings.conf file."""
        )
        settings_correct = False

    if not settings_correct:
        raise SystemExit

    # Check the config file for valid jamf subsets. This is based off the JAMF API and if it's not right we can't map fields over to SNIPE properly.
    logging.debug(
        "Checking the settings.conf file for valid JAMF subsets of the JAMF API so mapping can occur properly."
    )
    for key in config["computers-api-mapping"]:
        jamfsplit = config["computers-api-mapping"][key].split()
        if jamfsplit[0] in validsubset:
            logging.info("Found subset %s: Acceptable", jamfsplit[0])
            continue
        logging.error(
            "Found invalid subset: %s in the settings.conf file.\nThis is not in the acceptable list of subsets. Check your settings.conf\n Valid subsets are: %s",
            jamfsplit[0],
            ", ".join(validsubset),
        )
        raise SystemExit("Invalid Subset found in settings.conf")

    snipe_it = snipe.Snipe(config["snipe-it"]["url"], config["snipe-it"]["apiKey"])
    jamf_api = jamf.Jamf(
        config["jamf"]["url"], config["jamf"]["username"], config["jamf"]["password"]
    )

    # Make sure our services are up
    logging.info("SSL Verification is set to: %s", not USER_ARGS.do_not_verify_ssl)
    logging.info("Running tests to see if hosts are up.")
    try:
        snipe_it.check_connection()
        snipe_up = True
    except Exception as exception:  # pylint: disable=broad-except
        logging.exception(exception)
        snipe_up = False

    try:
        jamf_api.check_connection()
        jamf_up = True
    except Exception as exception:  # pylint: disable=broad-except
        logging.exception(exception)
        jamf_up = False

    if not jamf_up or not snipe_up:
        raise SystemExit("Error: Host could not be contacted.")

    logging.info("Finished running our tests.")

    ### Get Started ###
    # Retrieve the ID of the manufacturer with the name "Apple", either from config
    # or from Snipe-IT
    apple_manufacturer_id = config["snipe-it"].get("manufacturer_id", None)
    if apple_manufacturer_id is None:
        try:
            apple_manufacturer_id = snipe_it.get_apple_manufacturer()
        except ValueError:
            logging.critical(
                "Failed to find a manufacturer on your Snipe instance with the name 'Apple' and you did not set one in the configuration file. Make sure the 'Apple' manufacturer exists or set the manufacturer_id in settings.conf."
            )
            sys.exit(1)
    logging.debug(
        "Snipe-IT 'Apple' Manufacturer ID is set to %s", apple_manufacturer_id
    )

    # Get a list of known models from Snipe
    logging.info("Getting a list of computer models that snipe knows about.")
    snipemodels = snipe_it.get_models()
    logging.debug(
        "Parsing the %i model results for models with model numbers.",
        len(snipemodels),
    )
    model_numbers = {}
    for model in snipemodels:
        if model["model_number"] == "":
            logging.debug(
                "The model, %s, did not have a model number. Skipping.", model["name"]
            )
            continue
        model_numbers[model["model_number"]] = model["id"]
    logging.info("Our list of models has %s entries.", len(model_numbers))
    logging.debug(
        "Here's the list of the %s models and their id's that we were able to collect:\n%s",
        len(model_numbers),
        model_numbers,
    )

    # Get the IDS of all active assets.
    jamf_computer_list = jamf_api.get_computers()
    jamf_mobile_list = jamf_api.get_mobile_devices()
    jamf_types = {"computers": jamf_computer_list, "mobile_devices": jamf_mobile_list}

    total_assets = 0
    if USER_ARGS.computers:
        total_assets = len(jamf_types["computers"]["computers"])
    elif USER_ARGS.mobiles:
        total_assets = len(jamf_types["mobile_devices"]["mobile_devices"])
    else:
        for jamf_type in jamf_types:
            total_assets += len(jamf_types[jamf_type][jamf_type])

    # Make sure we have a good list.
    if jamf_computer_list is not None:
        logging.info(
            "Received a list of JAMF assets that had %s entries.", total_assets
        )
    else:
        logging.error(
            "We were not able to retreive a list of assets from your JAMF instance. It's likely that your settings, or credentials are incorrect. Check your settings.conf and verify you can make API calls outside of this system with the credentials found in your settings.conf"
        )
        raise SystemExit("Unable to get JAMF Computers.")

    # After this point we start editing data, so quit if this is a dryrun
    if USER_ARGS.dryrun:
        raise SystemExit("Dryrun: Complete.")

    # From this point on, we're editing data.
    logging.info("Starting to Update Inventory")
    current_asset = 0
    errors = 0
    seen_assets = []

    for jamf_type in jamf_types:
        if USER_ARGS.computers:
            if jamf_type != "computers":
                continue
        if USER_ARGS.mobiles:
            if jamf_type != "mobile_devices":
                continue

        # Preload all the assets of this type
        logging.info("Starting to retrieve %s", jamf_type)
        asset_ids = [asset["id"] for asset in jamf_types[jamf_type][jamf_type]]
        if jamf_type == "computers":
            this_type_callable = jamf_api.get_computer
        else:
            this_type_callable = jamf_api.get_mobile_device

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        jamf_futures = {
            executor.submit(this_type_callable, asset_id) for asset_id in asset_ids
        }

        for jamf_future in concurrent.futures.as_completed(jamf_futures):
            jamf_return = jamf_future.result()
            if jamf_return is None:
                # The error was already logged by get_computers()
                errors += 1
                continue

            current_asset += 1
            logging.info(
                "Processing entry %s out of %s - JAMFID: %s - NAME: %s",
                current_asset,
                total_assets,
                jamf_return["general"]["id"],
                jamf_return["general"]["name"],
            )
            jamf_serial_number = jamf_return["general"]["serial_number"]

            seen_assets.append(jamf_serial_number)

            # Check that the model number exists in snipe, if not create it.
            if jamf_type == "computers":
                jamf_model_identifier = jamf_return["hardware"]["model_identifier"]
                if jamf_model_identifier not in model_numbers:
                    logging.info(
                        "Could not find a model ID in snipe for: %s",
                        jamf_model_identifier,
                    )
                    newmodel = {
                        "category_id": config["snipe-it"]["computer_model_category_id"],
                        "manufacturer_id": apple_manufacturer_id,
                        "name": jamf_return["hardware"]["model"],
                        "model_number": jamf_model_identifier,
                    }
                    if "computer_custom_fieldset_id" in config["snipe-it"]:
                        fieldset_split = config["snipe-it"][
                            "computer_custom_fieldset_id"
                        ]
                        newmodel["fieldset_id"] = fieldset_split
                    snipe_model_id = snipe_it.create_model(newmodel)
                    model_numbers[jamf_model_identifier] = snipe_model_id
            elif jamf_type == "mobile_devices":
                jamf_model_identifier = jamf_return["general"]["model_identifier"]
                if jamf_model_identifier not in model_numbers:
                    logging.info(
                        "Could not find a model ID in snipe for: %s",
                        jamf_model_identifier,
                    )
                    newmodel = {
                        "category_id": config["snipe-it"]["mobile_model_category_id"],
                        "manufacturer_id": apple_manufacturer_id,
                        "name": jamf_return["general"]["model"],
                        "model_number": jamf_model_identifier,
                    }
                    if "mobile_custom_fieldset_id" in config["snipe-it"]:
                        fieldset_split = config["snipe-it"]["mobile_custom_fieldset_id"]
                        newmodel["fieldset_id"] = fieldset_split
                    snipe_model_id = snipe_it.create_model(newmodel)
                    model_numbers[jamf_model_identifier] = snipe_model_id

            # Pass the SN from JAMF to search for a match in Snipe
            snipe_asset = snipe_it.get_asset_by_serial(jamf_serial_number)

            # Create a new asset if there's no match:
            if snipe_asset == "NoMatch":
                logging.info(
                    "Creating a new asset in snipe for JAMF ID %s - %s",
                    jamf_return["general"]["id"],
                    jamf_return["general"]["name"],
                )
                # This section checks to see if the asset tag was already put into JAMF, if not it creates one with with Jamf's ID.
                if jamf_return["general"]["asset_tag"] == "":
                    jamf_asset_tag = None
                    logging.debug(
                        "No asset tag found in Jamf, checking settings.conf for alternative specified field."
                    )
                    if "asset_tag" in config["snipe-it"]:
                        tag_split = config["snipe-it"]["asset_tag"].split()
                        try:
                            jamf_asset_tag = jamf_return[str(tag_split[0])][
                                str(tag_split[1])
                            ]
                        except:
                            raise SystemError(
                                "No such attribute {} in the jamf payload. Please check your settings.conf file".format(
                                    tag_split
                                )
                            )
                    if jamf_asset_tag is None or jamf_asset_tag == "":
                        logging.debug(
                            "No custom configuration found in settings.conf for asset tag name upon asset creation."
                        )
                        if jamf_type == "mobile_devices":
                            jamf_asset_tag = "jamfid-m-{}".format(
                                jamf_return["general"]["id"]
                            )
                        elif jamf_type == "computers":
                            jamf_asset_tag = "jamfid-{}".format(
                                jamf_return["general"]["id"]
                            )
                else:
                    jamf_asset_tag = jamf_return["general"]["asset_tag"]
                    logging.info(
                        "Asset tag found in Jamf, setting it to: %s", jamf_asset_tag
                    )
                # Create the payload
                if jamf_type == "mobile_devices":
                    logging.debug("Payload is being made for a mobile device")
                    model_id = str(jamf_return["general"]["model_identifier"])
                elif jamf_type == "computers":
                    logging.debug("Payload is being made for a computer")
                    model_id = str(jamf_return["hardware"]["model_identifier"])
                newasset = {
                    "asset_tag": jamf_asset_tag,
                    "model_id": model_numbers[model_id],
                    "name": jamf_return["general"]["name"],
                    "status_id": defaultStatus,
                    "serial": jamf_serial_number,
                    "notes": MANAGED_NOTES,
                }
                if jamf_serial_number == "Not Available":
                    logging.error(
                        "The serial number is not available in JAMF. This is normal for DEP enrolled devices that have not yet checked in for the first time. Since there's no serial number yet, we'll skip it for now."
                    )
                    errors += 1
                    continue
                try:
                    new_snipe_asset = snipe_it.create_asset(newasset)
                except snipe.AssetCreationError as e:
                    logging.exception(e)
                    logging.error(
                        "Failed to create asset with the following payload, the error message is above: %s",
                        newasset,
                    )
                    errors += 1
                    continue
                if USER_ARGS.users or USER_ARGS.users_force:
                    jamf_data_category, jamf_data_field = config["user-mapping"][
                        "jamf_api_field"
                    ].split()
                    if jamf_data_field not in jamf_return[jamf_data_category]:
                        logging.info(
                            "Couldn't find %s for this device in %s, not checking it out.",
                            jamf_data_field,
                            jamf_data_category,
                        )
                        continue
                    logging.info(
                        "Checking out new item %s to user %s",
                        jamf_return["general"]["name"],
                        jamf_return[str(jamf_data_category)][str(jamf_data_field)],
                    )
                    jamf_username = jamf_return[jamf_data_category][jamf_data_field]
                    if USER_ARGS.create_snipe_users:
                        create_user_if_not_exists(
                            snipe_it,
                            ALLOW_FUZZY_SEARCH,
                            jamf_return["location"]["realname"],
                            jamf_return["location"]["username"],
                            jamf_return["location"]["email_address"],
                        )
                    if not set_checked_out_user(
                        snipe_it, new_snipe_asset, jamf_username, ALLOW_FUZZY_SEARCH
                    ):
                        errors += 1

            # Log an error if there's an issue, or more than once match.
            elif snipe_asset == "MultiMatch":
                logging.error(
                    "WARN: You need to resolve multiple assets with the same serial number in your inventory. If you can't find them in your inventory, you might need to purge your deleted records. You can find that in the Snipe Admin settings. Skipping serial number %s for now.",
                    jamf_serial_number,
                )
                errors += 1
            elif snipe_asset == "ERROR":
                logging.error(
                    "We got an error when looking up serial number %s in snipe, which shouldn't happen at this point. Check your snipe instance and setup. Skipping for now.",
                    jamf_serial_number,
                )
                errors += 1

            else:
                # Only update if JAMF has more recent info.
                snipe_id = snipe_asset["id"]
                snipe_time = snipe_asset["updated_at"]["datetime"]
                snipe_serial = snipe_asset["serial"]
                if jamf_type == "computers":
                    jamf_time = jamf_return["general"]["report_date"]
                elif jamf_type == "mobile_devices":
                    jamf_time = jamf_return["general"]["last_inventory_update"]
                # Check to see that the JAMF record is newer than the previous Snipe update, or if it is a new record in Snipe
                if (jamf_time > snipe_time) or (USER_ARGS.force):
                    if USER_ARGS.force:
                        logging.debug(
                            "Forced the Update regardless of the timestamps below."
                        )
                    logging.debug(
                        "Updating the Snipe asset because JAMF has a more recent timestamp: %s > %s or the Snipe Record is new",
                        jamf_time,
                        snipe_time,
                    )
                    for snipekey in config["{}-api-mapping".format(jamf_type)]:
                        jamfsplit = config["{}-api-mapping".format(jamf_type)][
                            snipekey
                        ].split()
                        for i, item in enumerate(jamfsplit):
                            try:
                                item = int(item)
                            except ValueError:
                                logging.debug("%s is not an integer", item)
                            if i == 0:
                                jamf_value = jamf_return[item]
                            else:
                                if jamfsplit[0] == "extension_attributes":
                                    for attribute in jamf_value:
                                        if attribute["id"] == item:
                                            jamf_value = attribute["value"]
                                else:
                                    jamf_value = jamf_value[item]
                        payload = {snipekey: jamf_value}
                        latestvalue = jamf_value

                        # Need to check that we're not needlessly updating the asset.
                        # If it's a custom value it'll fail the first section and send it to except section that will parse custom sections.
                        try:
                            if snipe_asset[snipekey] != latestvalue:
                                snipe_it.update_asset(snipe_id, payload)
                            else:
                                logging.debug(
                                    "Skipping the payload, because it already exits."
                                )
                        except (KeyError, IndexError):
                            logging.debug(
                                "The snipekey lookup failed, which means it's a custom field. Parsing those to see if it needs to be updated or not."
                            )
                            needsupdate = False
                            for custom_field in snipe_asset["custom_fields"]:
                                if (
                                    snipe_asset["custom_fields"][custom_field]["field"]
                                    == snipekey
                                ):
                                    if (
                                        snipe_asset["custom_fields"][custom_field][
                                            "value"
                                        ]
                                        != latestvalue
                                    ):
                                        logging.debug(
                                            "Found the field, and the value needs to be updated from %s to %s",
                                            snipe_asset["custom_fields"][custom_field][
                                                "value"
                                            ],
                                            latestvalue,
                                        )
                                        needsupdate = True
                            if needsupdate:
                                snipe_it.update_asset(snipe_id, payload)
                            else:
                                logging.debug(
                                    "Skipping the payload, because it already exists, or the Snipe key we're mapping to doesn't."
                                )
                    if (
                        (USER_ARGS.users)
                        and (snipe_asset["assigned_to"] is None) == USER_ARGS.users
                    ) or USER_ARGS.users_force:

                        if snipe_asset["status_label"]["status_meta"] in (
                            "deployable",
                            "deployed",
                        ):
                            jamf_data_category, jamf_data_field = config[
                                "user-mapping"
                            ]["jamf_api_field"].split()
                            if jamf_data_field not in jamf_return[jamf_data_category]:
                                logging.info(
                                    "Couldn't find %s for this device in %s, not checking it out.",
                                    jamf_data_field,
                                    jamf_data_category,
                                )
                                continue
                            jamf_username = jamf_return[jamf_data_category][
                                jamf_data_field
                            ]
                            if USER_ARGS.create_snipe_users:
                                create_user_if_not_exists(
                                    snipe_it,
                                    ALLOW_FUZZY_SEARCH,
                                    jamf_return["location"]["realname"],
                                    jamf_return["location"]["username"],
                                    jamf_return["location"]["email_address"],
                                )
                            if not set_checked_out_user(
                                snipe_it,
                                snipe_asset,
                                jamf_username,
                                ALLOW_FUZZY_SEARCH,
                            ):
                                errors += 1
                        else:
                            logging.error(
                                "Can't checkout %s since the status isn't set to deployable",
                                jamf_return["general"]["name"],
                            )
                            errors += 1

                else:
                    logging.info(
                        "Snipe Record is newer than the JAMF record. Nothing to sync. If this wrong, then force an inventory update in JAMF"
                    )
                    logging.debug(
                        "Not updating the Snipe asset because Snipe has a more recent timestamp: %s < %s",
                        jamf_time,
                        snipe_time,
                    )

        executor.shutdown()

    logging.info("Removing assets that jamf2snipe managed and no longer exist in Jamf")
    for asset in snipe_it.get_assets():
        asset_serial = asset["serial"]
        if asset["notes"] == MANAGED_NOTES and asset_serial not in seen_assets:
            asset_id = asset["id"]
            logging.info(
                "Removing asset ID '%s' with serial number '%s'", asset_id, asset_serial
            )
            try:
                snipe_it.remove_asset(asset_id)
            except snipe.AssetDeletionError as e:
                logging.exception(e)
                errors += 1

    logging.info("Total amount of API calls made to snipe-it: %i", snipe_it.api_count)
    logging.info("Total amount of API calls made to jamf: %i", jamf_api.api_count)

    if errors > 0:
        logging.error(
            "Done. %i assets failed to update. The details are in the log output above.",
            errors,
        )
        sys.exit(1)
    else:
        logging.info("Done!")


if __name__ == "__main__":
    main()
