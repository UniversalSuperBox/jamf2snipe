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
    GLPv3

CONFIGURATION:
    These settings are commonly found in the settings.conf file.

    This setting sets the Snipe Asset status when creating a new asset. By default it's set to 4 (Pending).
    defaultStatus = 4

    You can associate snipe hardware keys in the [api-mapping] section, to to a JAMF keys so it associates
    the jamf values into snipe. The default example associates information that exists by default in both
    Snipe and JAMF.  The Key value is the exact name of the snipe key name.
    Value1 is the "Subset" (JAMF's wording not mine) name, and the Value2 is the JAMF key name.
    Note that MAC Address are a custom value in SNIPE by default and you can use it as an example.

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
        "configuration_profiles"
]


import argparse
import configparser
import logging
import sys
import time

import requests

import snipe

# Set us up for using runtime arguments by defining them.
runtimeargs = argparse.ArgumentParser()
runtimeargs.add_argument("-v", "--verbose", help="Sets the logging level to INFO and gives you a better idea of what the script is doing.", action="store_true")
runtimeargs.add_argument("--dryrun", help="This checks your config and tries to contact both the JAMFPro and Snipe-it instances, but exits before updating or syncing any assets.", action="store_true")
runtimeargs.add_argument("-d", "--debug", help="Sets logging to include additional DEBUG messages.", action="store_true")
runtimeargs.add_argument("--do_not_update_jamf", help="Does not update Jamf with the asset tags stored in Snipe.", action="store_false")
runtimeargs.add_argument('--do_not_verify_ssl', help="Skips SSL verification for all requests. Helpful when you use self-signed certificate.", action="store_true")
runtimeargs.add_argument("-r", "--ratelimited", help="Puts a half second delay between Snipe IT API calls to adhere to the standard 120/minute rate limit", action="store_true")
runtimeargs.add_argument("-f", "--force", help="Updates the Snipe asset with information from Jamf every time, despite what the timestamps indicate.", action="store_true")
user_opts = runtimeargs.add_mutually_exclusive_group()
user_opts.add_argument("-u", "--users", help="Checks out the item to the current user in Jamf if it's not already deployed", action="store_true")
user_opts.add_argument("-ui", "--users_inverse", help="Checks out the item to the current user in Jamf if it's already deployed", action="store_true")
user_opts.add_argument("-uf", "--users_force", help="Checks out the item to the user specified in Jamf no matter what", action="store_true")
user_opts.add_argument("-uns", "--users_no_search", help="Doesn't search for any users if the specified fields in Jamf and Snipe don't match. (case insensitive)", action="store_true")
type_opts = runtimeargs.add_mutually_exclusive_group()
type_opts.add_argument("-m", "--mobiles", help="Runs against the Jamf mobiles endpoint only.", action="store_true")
type_opts.add_argument("-c", "--computers", help="Runs against the Jamf computers endpoint only.", action="store_true")
USER_ARGS = runtimeargs.parse_args()

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
if 'snipe-it' not in set(config):
    logging.debug("No valid config found in: /opt Checking for a settings.conf in /etc/jamf2snipe ...")
    config.read('/etc/jamf2snipe/settings.conf')
if 'snipe-it' not in set(config):
    logging.debug("No valid config found in /etc Checking for a settings.conf in current directory ...")
    config.read("settings.conf")
if 'snipe-it' not in set(config):
    logging.debug("No valid config found in current folder.")
    logging.error("No valid settings.conf was found. We'll need to quit while you figure out where the settings are at. You can check the README for valid locations.")
    raise SystemExit("Error: No valid settings.conf - Exiting.")

logging.info("Great, we found a settings file. Let's get started by parsing all fo the settings.")

# Set some Variables from the settings.conf:
# This is the address, cname, or FQDN for your JamfPro instance.
JAMF_BASE = config['jamf']['url']
logging.info("The configured JAMFPro base url is: %s", JAMF_BASE)
JAMF_API_USER = config['jamf']['username']
logging.info("The configured JAMFPro username we'll be connecting with is: %s", JAMF_API_USER)
JAMF_API_PASSWORD = config['jamf']['password']
logging.debug("The configured password to access the API is: %s", JAMF_API_PASSWORD)

# This is the address, cname, or FQDN for your snipe-it instance.
defaultStatus = config['snipe-it']['defaultStatus']
logging.info("The default status we'll be setting updated computer to is: %s (I sure hope this is a number or something is probably wrong)", defaultStatus)

#TODO: Fail if defaultStatus is not an integer, assuming Snipe-IT can't accept anything but integer statuses.

### Setup Some Functions ###
SNIPE_API_COUNT = 0
FIRST_SNIPE_CALL = None
RATE_LIMIT_SNIPE = USER_ARGS.ratelimited

def check_server_status(session, base_url):
    """Checks if a server is responding with 200 OK or 401 Unauthorized at a given URL.

    :param session:
        requests.Session object to use for this request. If none is provided,
        one will be created for you.

    :param base_url:
        URL to request

    :returns: True if the host appears to be up, False if it does not.
    """

    try:
        r = session.get(base_url)
        # We'll receive a 401 from the JAMF server telling us to authenticate.
        # That's okay, we only want to know it's up.
        if r.status_code != 401:
            r.raise_for_status()
    except Exception as exception: #pylint: disable=broad-except
        logging.exception(exception)
        logging.error('%s did not return 200 OK or 401 Unauthorized. \nPlease check the your config in the settings.conf file.', base_url)
        return False

    logging.info('We were able to get a good response from your JAMFPro instance.')
    return True

def jamf_request_handler(r, *args, **kwargs): #pylint: disable=unused-argument,invalid-name
    """Handles rate limiting for the JAMF server.

    This function should be passed as a response hook on every request made to
    the JAMF server. The easiest way to ensure this happens is to use the
    requests.Session made for JAMF requests.
    """
    if r.status_code != 200 and b'policies.ratelimit.QuotaViolation' in r.content:
        # This case should only occur with JAMF's developer portal
        logging.warning('JAMFPro Ratelimit exceeded - error code %s. Pausing for 75 seconds.', r.status_code)
        time.sleep(75)
        logging.info("Finished waiting. Retrying lookup...")
        newresponse = JAMF_SESSION.send(r.request)
        return newresponse
    return r

def session_setup(service, verify_ssl=True):
    """Returns a requests.Session object set up for making requests to a service

    :param service:
        "snipe" or "jamf", determines whether the session is set up for
        querying Snipe-IT or JAMF, respectively.

    :param verify_ssl:
        Whether the created session should verify SSL/TLS certificates or not.
        See https://requests.readthedocs.io/en/master/api/#requests.Session.verify
    """
    session = requests.Session()
    if service == "jamf":
        session.hooks["response"].append(jamf_request_handler)
        session.headers.update({'Accept': 'application/json'})
        session.auth = (JAMF_API_USER, JAMF_API_PASSWORD)
    else:
        raise ValueError("Incorrect service specified")
    session.verify = verify_ssl
    return session

def get_jamf_computers(session):
    """Retrieves a list of all computers from the JAMF instance.

    The JAMF instance is specified by the global variable ``JAMF_BASE``

    :param session:
        requests.Session object to use for this request. This session must have
        all headers needed for the request, including authorization headers.
    """
    api_url = '{0}/JSSResource/computers'.format(JAMF_BASE)
    logging.debug('Calling for JAMF computers against: %s\n The username, passwords, and headers for this GET requestcan be found near the beginning of the output.', api_url)
    response = session.get(api_url)
    if response.status_code == 200:
        logging.debug("Got back a valid 200 response code.")
        return response.json()
    logging.warning('Received an invalid status code when trying to retreive JAMF Device list:%s - %s', response.status_code, response.content)
    logging.debug("Returning a null value for the function.")
    return None

def get_jamf_mobiles(session):
    """Retrieves a list of all mobile devices from the JAMF instance.

    The JAMF instance is specified by the global variable ``JAMF_BASE``

    :param session:
        requests.Session object to use for this request. This session must have
        all headers needed for the request, including authorization headers.
    """
    api_url = '{0}/JSSResource/mobiledevices'.format(JAMF_BASE)
    logging.debug('Calling for JAMF mobiles against: %s\n The username, passwords, and headers for this GET requestcan be found near the beginning of the output.', api_url)
    response = session.get(api_url)
    if response.status_code == 200:
        logging.debug("Got back a valid 200 response code.")
        return response.json()
    logging.warning('Received an invalid status code when trying to retreive JAMF Device list:%s - %s', response.status_code, response.content)
    logging.debug("Returning a null value for the function.")
    return None

def search_jamf_asset(jamf_id, session):
    """Retrieves a single computer from the JAMF instance by ID.

    The JAMF instance is specified by the global variable ``JAMF_BASE``

    :param jamf_id: JAMF instance's unique ID value identifying this computer.

    :param session:
        requests.Session object to use for this request. This session must have
        all headers needed for the request, including authorization headers.
    """
    api_url = "{}/JSSResource/computers/id/{}".format(JAMF_BASE, jamf_id)
    response = session.get(api_url)
    if response.status_code == 200:
        logging.debug("Got back a valid 200 response code.")
        jsonresponse = response.json()
        logging.debug("Returning: %s", jsonresponse['computer'])
        return jsonresponse['computer']
    logging.warning('JAMFPro responded with error code:%s when we tried to look up id: %s', response, jamf_id)
    logging.debug("Returning a null value for the function.")
    return None

def search_jamf_mobile(jamf_id, session):
    """Retrieves a single mobile device from the JAMF instance by ID.

    The JAMF instance is specified by the global variable ``JAMF_BASE``

    :param jamf_id: JAMF instance's unique ID value identifying this mobile
        device.

    :param session:
        requests.Session object to use for this request. This session must have
        all headers needed for the request, including authorization headers.
    """
    api_url = "{}/JSSResource/mobiledevices/id/{}".format(JAMF_BASE, jamf_id)
    response = session.get(api_url)
    if response.status_code == 200:
        logging.debug("Got back a valid 200 response code.")
        jsonresponse = response.json()
        logging.debug("Returning: %s", jsonresponse['mobile_device'])
        return jsonresponse['mobile_device']
    logging.warning('JAMFPro responded with error code:%s when we tried to look up id: %s', response, jamf_id)
    logging.debug("Returning a null value for the function.")
    return None

def update_jamf_asset_tag(jamf_id, asset_tag, session):
    """Updates the asset tag field on a single computer in JAMF.

    The JAMF instance is specified by the global variable ``JAMF_BASE``

    :param jamf_id: JAMF instance's unique ID value identifying this computer.

    :param asset_tag: The new value for the asset tag field for this computer
        in the JAMF instance.

    :param session:
        requests.Session object to use for this request. This session must have
        all headers needed for the request, including authorization headers.
    """
    api_url = "{}/JSSResource/computers/id/{}".format(JAMF_BASE, jamf_id)
    payload = """<?xml version="1.0" encoding="UTF-8"?><computer><general><id>{}</id><asset_tag>{}</asset_tag></general></computer>""".format(jamf_id, asset_tag)
    logging.debug('Making Get request against: %s\nPayload for the PUT request is: %s\nThe username, password, and headers can be found near the beginning of the output.', api_url, payload)
    response = session.put(api_url, data=payload)
    if response.status_code == 201:
        logging.debug("Got a 201 response. Returning: True")
        return True
    if response.status_code == 200:
        logging.debug("Got a 200 response code. Returning the response: %s", response)
        return response.json()
    logging.warning('Got back an error response code:%s - %s', response.status_code, response.content)
    return None

def update_jamf_mobiledevice_asset_tag(jamf_id, asset_tag, session):
    """Updates the asset tag field on a single mobile device in JAMF.

    The JAMF instance is specified by the global variable ``JAMF_BASE``

    :param jamf_id: JAMF instance's unique ID value identifying this mobile
        device.

    :param asset_tag: The new value for the asset tag field for this mobile
        device in the JAMF instance.

    :param session:
        requests.Session object to use for this request. This session must have
        all headers needed for the request, including authorization headers.
    """
    api_url = "{}/JSSResource/mobiledevices/id/{}".format(JAMF_BASE, jamf_id)
    payload = """<?xml version="1.0" encoding="UTF-8"?><mobile_device><general><id>{}</id><asset_tag>{}</asset_tag></general></mobile_device>""".format(jamf_id, asset_tag)
    logging.debug('Making Get request against: %s\nPayload for the PUT request is: %s\nThe username, password, and headers can be found near the beginning of the output.', api_url, payload)
    response = session.put(api_url, data=payload)
    if response.status_code == 201:
        logging.debug("Got a 201 response. Returning: True")
        return True
    if response.status_code == 200:
        logging.debug("Got a 200 response code. Returning the response: %s", response)
        return response.json()
    logging.warning('Got back an error response code:%s - %s', response.status_code, response.content)
    return None

JAMF_SESSION = session_setup("jamf", verify_ssl=not USER_ARGS.do_not_verify_ssl)

def main():
    # Do some tests to see if the user has updated their settings.conf file
    settings_correct = True
    if 'api-mapping' in config:
        logging.error("Looks like you're using the old method for api-mapping. Please use computers-api-mapping and mobile_devices-api-mapping.")
        settings_correct = False
    if 'user-mapping' not in config and (USER_ARGS.users or USER_ARGS.users_force or USER_ARGS.users_inverse):
        logging.error("""You've chosen to check out assets to users in some capacity using a cmdline switch, but not specified how you want to
        search Snipe IT for the users from Jamf. Make sure you have a 'user-mapping' section in your settings.conf file.""")
        settings_correct = False

    if not settings_correct:
        raise SystemExit

    # Check the config file for valid jamf subsets. This is based off the JAMF API and if it's not right we can't map fields over to SNIPE properly.
    logging.debug("Checking the settings.conf file for valid JAMF subsets of the JAMF API so mapping can occur properly.")
    for key in config['computers-api-mapping']:
        jamfsplit = config['computers-api-mapping'][key].split()
        if jamfsplit[0] in validsubset:
            logging.info('Found subset %s: Acceptable', jamfsplit[0])
            continue
        logging.error("Found invalid subset: %s in the settings.conf file.\nThis is not in the acceptable list of subsets. Check your settings.conf\n Valid subsets are: %s", jamfsplit[0], ', '.join(validsubset))
        raise SystemExit("Invalid Subset found in settings.conf")

    snipe_it = snipe.Snipe(config['snipe-it']['url'], config['snipe-it']['apiKey'])

    # Make sure our services are up
    logging.info("SSL Verification is set to: %s", not USER_ARGS.do_not_verify_ssl)
    logging.info("Running tests to see if hosts are up.")
    try:
        snipe_it.check_connection()
        snipe_up = True
    except Exception as exception: #pylint: disable=broad-except
        logging.exception(exception)
        snipe_up = False

    #TODO: We should test that we can actually connect with the API keys, but
    # connectivity testing is a good start.
    jamf_up = check_server_status(JAMF_SESSION, JAMF_BASE)

    if not jamf_up or not snipe_up:
        raise SystemExit("Error: Host could not be contacted.")

    logging.info("Finished running our tests.")

    ### Get Started ###
    # Retrieve the ID of the manufacturer with the name "Apple", either from config
    # or from Snipe-IT
    apple_manufacturer_id = config['snipe-it'].get('manufacturer_id', None)
    if apple_manufacturer_id is None:
        try:
            apple_manufacturer_id = snipe_it.get_snipe_apple_manufacturer()
        except ValueError:
            logging.critical("Failed to find a manufacturer on your Snipe instance with the name 'Apple' and you did not set one in the configuration file. Make sure the 'Apple' manufacturer exists or set the manufacturer_id in settings.conf.")
            sys.exit(1)
    logging.debug("Snipe-IT 'Apple' Manufacturer ID is set to %s", apple_manufacturer_id)

    # Get a list of known models from Snipe
    logging.info("Getting a list of computer models that snipe knows about.")
    snipemodels = snipe_it.get_snipe_models()
    logging.debug("Parsing the %s model results for models with model numbers.", len(snipemodels['rows']))
    model_numbers = {}
    for model in snipemodels['rows']:
        if model['model_number'] == "":
            logging.debug("The model, %s, did not have a model number. Skipping.", model['name'])
            continue
        model_numbers[model['model_number']] = model['id']
    logging.info("Our list of models has %s entries.", len(model_numbers))
    logging.debug("Here's the list of the %s models and their id's that we were able to collect:\n%s", len(model_numbers), model_numbers)

    # Get the IDS of all active assets.
    jamf_computer_list = get_jamf_computers(JAMF_SESSION)
    jamf_mobile_list = get_jamf_mobiles(JAMF_SESSION)
    jamf_types = {
        'computers': jamf_computer_list,
        'mobile_devices': jamf_mobile_list
    }

    # Get a list of users from Snipe if the user has specified
    # they're syncing users

    if USER_ARGS.users or USER_ARGS.users_force or USER_ARGS.users_inverse:
        snipe_users = snipe_it.get_snipe_users()

    total_assets = 0
    if USER_ARGS.computers:
        total_assets = len(jamf_types['computers']['computers'])
    elif USER_ARGS.mobiles:
        total_assets = len(jamf_types['mobile_devices']['mobile_devices'])
    else:
        for jamf_type in jamf_types:
            total_assets += len(jamf_types[jamf_type][jamf_type])

    # Make sure we have a good list.
    if jamf_computer_list is not None:
        logging.info('Received a list of JAMF assets that had %s entries.', total_assets)
    else:
        logging.error("We were not able to retreive a list of assets from your JAMF instance. It's likely that your settings, or credentials are incorrect. Check your settings.conf and verify you can make API calls outside of this system with the credentials found in your settings.conf")
        raise SystemExit("Unable to get JAMF Computers.")

    # After this point we start editing data, so quit if this is a dryrun
    if USER_ARGS.dryrun:
        raise SystemExit("Dryrun: Complete.")

    # From this point on, we're editing data.
    logging.info('Starting to Update Inventory')
    current_asset = 0

    for jamf_type in jamf_types:
        if USER_ARGS.computers:
            if jamf_type != 'computers':
                continue
        if USER_ARGS.mobiles:
            if jamf_type != 'mobile_devices':
                continue
        for jamf_asset in jamf_types[jamf_type][jamf_type]:
            current_asset += 1
            logging.info("Processing entry %s out of %s - JAMFID: %s - NAME: %s", current_asset, total_assets, jamf_asset['id'], jamf_asset['name'])
            # Search through the list by ID for all asset information\
            if jamf_type == 'computers':
                jamf = search_jamf_asset(jamf_asset['id'], session=JAMF_SESSION)
            elif jamf_type == 'mobile_devices':
                jamf = search_jamf_mobile(jamf_asset['id'], session=JAMF_SESSION)
            if jamf is None:
                logging.warning("JAMF did not return a device for ID %s for type %s", jamf_asset['id'], jamf_type)
                continue

            # Check that the model number exists in snipe, if not create it.
            if jamf_type == 'computers':
                jamf_model_identifier = jamf['hardware']['model_identifier']
                if jamf_model_identifier not in model_numbers:
                    logging.info("Could not find a model ID in snipe for: %s", jamf_model_identifier)
                    newmodel = {"category_id":config['snipe-it']['computer_model_category_id'], "manufacturer_id": apple_manufacturer_id, "name": jamf['hardware']['model'], "model_number": jamf_model_identifier}
                    if 'computer_custom_fieldset_id' in config['snipe-it']:
                        fieldset_split = config['snipe-it']['computer_custom_fieldset_id']
                        newmodel['fieldset_id'] = fieldset_split
                    snipe_model_id = snipe_it.create_snipe_model(newmodel)
                    model_numbers[jamf_model_identifier] = snipe_model_id
            elif jamf_type == 'mobile_devices':
                jamf_model_identifier = jamf['general']['model_identifier']
                if jamf_model_identifier not in model_numbers:
                    logging.info("Could not find a model ID in snipe for: %s", jamf_model_identifier)
                    newmodel = {"category_id":config['snipe-it']['mobile_model_category_id'], "manufacturer_id": apple_manufacturer_id, "name": jamf['general']['model'], "model_number": jamf_model_identifier}
                    if 'mobile_custom_fieldset_id' in config['snipe-it']:
                        fieldset_split = config['snipe-it']['mobile_custom_fieldset_id']
                        newmodel['fieldset_id'] = fieldset_split
                    snipe_model_id = snipe_it.create_snipe_model(newmodel)
                    model_numbers[jamf_model_identifier] = snipe_model_id

            # Pass the SN from JAMF to search for a match in Snipe
            snipe_asset = snipe_it.search_snipe_asset(jamf['general']['serial_number'])

            # Create a new asset if there's no match:
            if snipe_asset == 'NoMatch':
                logging.info("Creating a new asset in snipe for JAMF ID %s - %s", jamf['general']['id'], jamf['general']['name'])
                # This section checks to see if the asset tag was already put into JAMF, if not it creates one with with Jamf's ID.
                if jamf['general']['asset_tag'] == '':
                    jamf_asset_tag = None
                    logging.debug('No asset tag found in Jamf, checking settings.conf for alternative specified field.')
                    if 'asset_tag' in config['snipe-it']:
                        tag_split = config['snipe-it']['asset_tag'].split()
                        try:
                            jamf_asset_tag = jamf[str(tag_split[0])][str(tag_split[1])]
                        except:
                            raise SystemError('No such attribute {} in the jamf payload. Please check your settings.conf file'.format(tag_split))
                    if jamf_asset_tag is None or jamf_asset_tag == '':
                        logging.debug('No custom configuration found in settings.conf for asset tag name upon asset creation.')
                        if jamf_type == 'mobile_devices':
                            jamf_asset_tag = 'jamfid-m-{}'.format(jamf['general']['id'])
                        elif jamf_type == 'computers':
                            jamf_asset_tag = 'jamfid-{}'.format(jamf['general']['id'])
                else:
                    jamf_asset_tag = jamf['general']['asset_tag']
                    logging.info("Asset tag found in Jamf, setting it to: %s", jamf_asset_tag)
                # Create the payload
                if jamf_type == 'mobile_devices':
                    logging.debug("Payload is being made for a mobile device")
                    newasset = {'asset_tag': jamf_asset_tag, 'model_id': model_numbers[str(jamf['general']['model_identifier'])], 'name': jamf['general']['name'], 'status_id': defaultStatus, 'serial': jamf['general']['serial_number']}
                elif jamf_type == 'computers':
                    logging.debug("Payload is being made for a computer")
                    newasset = {'asset_tag': jamf_asset_tag, 'model_id': model_numbers[str(jamf['hardware']['model_identifier'])], 'name': jamf['general']['name'], 'status_id': defaultStatus, 'serial': jamf['general']['serial_number']}
                if jamf['general']['serial_number'] == 'Not Available':
                    logging.warning("The serial number is not available in JAMF. This is normal for DEP enrolled devices that have not yet checked in for the first time. Since there's no serial number yet, we'll skip it for now.")
                    continue
                new_snipe_asset = snipe_it.create_snipe_asset(newasset)
                if new_snipe_asset[0] != "AssetCreated":
                    continue
                if USER_ARGS.users or USER_ARGS.users_force or USER_ARGS.users_inverse:
                    jamf_data_category, jamf_data_field = config['user-mapping']['jamf_api_field'].split()
                    if jamf_data_field not in jamf[jamf_data_category]:
                        logging.info("Couldn't find %s for this device in %s, not checking it out.", jamf_data_field, jamf_data_category)
                        continue
                    logging.info('Checking out new item %s to user %s', jamf['general']['name'], jamf[str(jamf_data_category)][str(jamf_data_field)])
                    snipe_it.checkout_snipe_asset(jamf[jamf_data_category][jamf_data_field], new_snipe_asset[1].json()['payload']['id'], snipe_users, USER_ARGS.users_no_search, "NewAsset")

            # Log an error if there's an issue, or more than once match.
            elif snipe_asset == 'MultiMatch':
                logging.warning("WARN: You need to resolve multiple assets with the same serial number in your inventory. If you can't find them in your inventory, you might need to purge your deleted records. You can find that in the Snipe Admin settings. Skipping serial number %s for now.", jamf['general']['serial_number'])
            elif snipe_asset == 'ERROR':
                logging.error("We got an error when looking up serial number %s in snipe, which shouldn't happen at this point. Check your snipe instance and setup. Skipping for now.", jamf['general']['serial_number'])

            else:
                # Only update if JAMF has more recent info.
                snipe_id = snipe_asset['rows'][0]['id']
                snipe_time = snipe_asset['rows'][0]['updated_at']['datetime']
                if jamf_type == 'computers':
                    jamf_time = jamf['general']['report_date']
                elif jamf_type == 'mobile_devices':
                    jamf_time = jamf['general']['last_inventory_update']
                # Check to see that the JAMF record is newer than the previous Snipe update, or if it is a new record in Snipe
                if (jamf_time > snipe_time) or (USER_ARGS.force):
                    if USER_ARGS.force:
                        logging.debug("Forced the Update regardless of the timestamps below.")
                    logging.debug("Updating the Snipe asset because JAMF has a more recent timestamp: %s > %s or the Snipe Record is new", jamf_time, snipe_time)
                    for snipekey in config['{}-api-mapping'.format(jamf_type)]:
                        jamfsplit = config['{}-api-mapping'.format(jamf_type)][snipekey].split()
                        for i, item in enumerate(jamfsplit):
                            try:
                                item = int(item)
                            except ValueError:
                                logging.debug('%s is not an integer', item)
                            if i == 0:
                                jamf_value = jamf[item]
                            else:
                                if jamfsplit[0] == 'extension_attributes':
                                    for attribute in jamf_value:
                                        if attribute['id'] == item:
                                            jamf_value = attribute['value']
                                else:
                                    jamf_value = jamf_value[item]
                        payload = {snipekey: jamf_value}
                        latestvalue = jamf_value

                        # Need to check that we're not needlessly updating the asset.
                        # If it's a custom value it'll fail the first section and send it to except section that will parse custom sections.
                        try:
                            if snipe_asset['rows'][0][snipekey] != latestvalue:
                                snipe_it.update_snipe_asset(snipe_id, payload)
                            else:
                                logging.debug("Skipping the payload, because it already exits.")
                        except (KeyError, IndexError):
                            logging.debug("The snipekey lookup failed, which means it's a custom field. Parsing those to see if it needs to be updated or not.")
                            needsupdate = False
                            for custom_field in snipe_asset['rows'][0]['custom_fields']:
                                if snipe_asset['rows'][0]['custom_fields'][custom_field]['field'] == snipekey:
                                    if snipe_asset['rows'][0]['custom_fields'][custom_field]['value'] != latestvalue:
                                        logging.debug("Found the field, and the value needs to be updated from %s to %s", snipe_asset['rows'][0]['custom_fields'][custom_field]['value'], latestvalue)
                                        needsupdate = True
                            if needsupdate:
                                snipe_it.update_snipe_asset(snipe_id, payload)
                            else:
                                logging.debug("Skipping the payload, because it already exists, or the Snipe key we're mapping to doesn't.")
                    if ((USER_ARGS.users or USER_ARGS.users_inverse) and (snipe_asset['rows'][0]['assigned_to'] is None) == USER_ARGS.users) or USER_ARGS.users_force:

                        if snipe_asset['rows'][0]['status_label']['status_meta'] in ('deployable', 'deployed'):
                            jamf_data_category, jamf_data_field = config['user-mapping']['jamf_api_field'].split()
                            if jamf_data_field not in jamf[jamf_data_category]:
                                logging.info("Couldn't find %s for this device in %s, not checking it out.", jamf_data_field, jamf_data_category)
                                continue
                            snipe_it.checkout_snipe_asset(jamf[jamf_data_category][jamf_data_field], snipe_id, snipe_users, USER_ARGS.users_no_search, snipe_asset['rows'][0]['assigned_to'])
                        else:
                            logging.info("Can't checkout %s since the status isn't set to deployable", jamf['general']['name'])

                else:
                    logging.info("Snipe Record is newer than the JAMF record. Nothing to sync. If this wrong, then force an inventory update in JAMF")
                    logging.debug("Not updating the Snipe asset because Snipe has a more recent timestamp: %s < %s", jamf_time, snipe_time)

                # Update/Sync the Snipe Asset Tag Number back to JAMF
                # The user arg below is set to false if it's called, so this would fail if the user called it.
                snipe_asset_tag = snipe_asset['rows'][0]['asset_tag']
                jamf_asset_id = jamf['general']['id']
                if (jamf['general']['asset_tag'] != snipe_asset_tag) and USER_ARGS.do_not_update_jamf:
                    logging.info("JAMF doesn't have the same asset tag as SNIPE so we'll update it because it should be authoritative.")
                    if snipe_asset_tag:
                        if jamf_type == 'computers':
                            update_jamf_asset_tag(jamf_asset_id, snipe_asset_tag, session=JAMF_SESSION)
                            logging.info("Device is a computer, updating computer record")
                        elif jamf_type == 'mobile_devices':
                            update_jamf_mobiledevice_asset_tag(jamf_asset_id, snipe_asset_tag, session=JAMF_SESSION)
                            logging.info("Device is a mobile device, updating the mobile device record")

    logging.debug('Total amount of API calls made: %s', SNIPE_API_COUNT)

if __name__ == "__main__":
    main()
