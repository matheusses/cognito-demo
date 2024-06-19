import os
import random
import string
import requests


def lambda_handler(event, context):
    secret_login_code: str
    if not event['request']['session'] or not len(event['request']['session']):
        # This is a new auth session
        # Generate a new secret login code and mail it to the user
        secret_login_code = ''.join(random.choices(string.digits, k=6))
        send_sms(event['request']['userAttributes']['phone_number'], secret_login_code)
    else:
        # There's an existing session. Don't generate new digits but
        # re-use the code from the current session. This allows the user to
        # make a mistake when keying in the code and to then retry, rather
        # than needing to email the user an all-new code again.    
        previous_challenge = event['request']['session'][-1]
        secret_login_code = previous_challenge['challengeMetadata'].split('-')[1]

    # This is sent back to the client app
    event['response']['publicChallengeParameters'] = {
        'email': event['request']['userAttributes']['phone_number']
    }

    # Add the secret login code to the private challenge parameters
    # so it can be verified by the "Verify Auth Challenge Response" trigger
    event['response']['privateChallengeParameters'] = {'secretLoginCode': secret_login_code}

    # Add the secret login code to the session so it is available
    # in a next invocation of the "Create Auth Challenge" trigger
    event['response']['challengeMetadata'] = f'CODE-{secret_login_code}'

    return event


def send_sms(phone_number: str, secret_login_code: str):
    sms_service_url = os.environ['NOTIFICATION_SERVICE_URL']
    payload = {
      "channel_code": "sms",
      "template_code": "driver_login_token",
      "channel_variables": {
        "phone": phone_number,
        "is_transactional": True
      },
      "template_variables": {
        "token": secret_login_code
      }
    }

    headers={"User-Agent": "[cognito][lambda]create_auth_challenge"},

    response = requests.post(url=sms_service_url, headers=headers, json=payload)
    return response