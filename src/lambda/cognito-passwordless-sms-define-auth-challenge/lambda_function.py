import json

def lambda_handler(event, context):
    if 'session' in event['request'] and any(attempt['challengeName'] != 'CUSTOM_CHALLENGE' for attempt in event['request']['session']):
        # We only accept custom challenges; fail auth
        event['response']['issueTokens'] = False
        event['response']['failAuthentication'] = True
    elif 'session' in event['request'] and len(event['request']['session']) >= 3 and event['request']['session'][-1]['challengeResult'] == False:
        # The user provided a wrong answer 3 times; fail auth
        event['response']['issueTokens'] = False
        event['response']['failAuthentication'] = True
    elif 'session' in event['request'] and len(event['request']['session']) and event['request']['session'][-1]['challengeName'] == 'CUSTOM_CHALLENGE' and event['request']['session'][-1]['challengeResult'] == True:
        # The user provided the right answer; succeed auth
        event['response']['issueTokens'] = True
        event['response']['failAuthentication'] = False
    else:
        # The user did not provide a correct answer yet; present challenge
        event['response']['issueTokens'] = False
        event['response']['failAuthentication'] = False
        event['response']['challengeName'] = 'CUSTOM_CHALLENGE'

    return event