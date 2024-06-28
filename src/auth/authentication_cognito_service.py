import boto3
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
from decouple import config
import random
import string
import json



class AuthenticationCognitoService:
    def __init__(self, env='loggi-stg'):
        config('ENV', env)
        self._user_pool_id = config('USER_POOL_ID')
        self._client_id = config('CLIENT_ID')
        self._secret_key =  config('SECRET_KEY')
        _region = config('REGION')
        _profile_name = config('PROFILE_NAME')

        # nano ~/.aws/config -> profile name
        self._session = boto3.Session(profile_name=_profile_name,region_name=_region)
        self._client = self._session.client('cognito-idp')



    def generate_random_password(self, length=10):
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")

        # Ensure each category has at least one character
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]

        # Fill the rest of the password length with random characters
        if length > 4:
            characters = string.ascii_letters + string.digits + string.punctuation
            password += [random.choice(characters) for _ in range(length - 4)]

        # Shuffle the list to ensure randomness
        random.shuffle(password)

        return ''.join(password)



    def __get_secret_hash(self, username):
        message = username + self._client_id
        dig = hmac.new(
            key=self._secret_key.encode('UTF-8'),
            msg=message.encode('UTF-8'),
            digestmod=hashlib.sha256
        ).digest()
        secret_hash = base64.b64encode(dig).decode()
        return secret_hash


    def create_user(self, email, phone_number):
        client = boto3.client('cognito-idp')

        random_password = self.generate_random_password()

        response = client.admin_create_user(
            UserPoolId=self._user_pool_id,
            Username=email,
            UserAttributes=[
            {
                'Name': 'email',
                'Value': email
            },
            {
                'Name': 'phone_number',
                'Value': phone_number
            },
            {
                'Name': 'email_verified',
                'Value': 'true'
            }, 
            {
                'Name': 'phone_number_verified',
                'Value': 'true'
            }
            ],
            TemporaryPassword=random_password,
            MessageAction='SUPPRESS'  # Not sending the invitation email/SMS
            )
        # Set the user password to the generated password
        client.admin_set_user_password(
            UserPoolId=self._user_pool_id,
            Username=email,
            Password=random_password,
            Permanent=True
        )

        return response


    def get_username_by_phone_number(self, phone_number):
        try:
            response = self._client.list_users(
                UserPoolId=self._user_pool_id,
                Filter=f'phone_number = "{phone_number}"',
                Limit=1
            )
            if response['Users']:
                username = response['Users'][0]['Username']
                return username
            else:
                print(f"No user found with phone number: {phone_number}")
                return None
        except self._client.exceptions.InvalidParameterException as e:
            print(f"InvalidParameterException: {e}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None


    def update_user(self, username, uuid, access):
        response = self._client.admin_update_user_attributes(
            UserPoolId=self._user_pool_id,
            Username=username,
            UserAttributes=[
                {'Name': 'phone_number_verified', 'Value': 'true'},
                {'Name': 'email_verified', 'Value': 'true'},
                {'Name': 'custom:uuid', 'Value': uuid},
                {'Name': 'custom:access', 'Value': json.dumps(access)}
            ]
        )
        print(response)


    def update_set_user_password(self, username):
        self._client.admin_set_user_password(
        UserPoolId=self._user_pool_id,
        Username=username,
        Password=self.generate_random_password(),
        Permanent=True
    )


    def initiate_auth(self, user_name):
        response = self._client.initiate_auth(
            AuthFlow='CUSTOM_AUTH',
            AuthParameters={
                'USERNAME': user_name,
                'SECRET_HASH': self.__get_secret_hash(user_name),
            },
            ClientId=self._client_id,
        )
        session = response['Session']
        print("Auth initiated:", session)
        return session


    def confirm_user_signup(self, username, confirmation_code):
        try:
            response = self._client.confirm_sign_up(
                ClientId=self._client_id,
                SecretHash=self.__get_secret_hash(username),
                Username=username,
                ConfirmationCode=confirmation_code,
                ForceAliasCreation=False
            )
            return response
        except ClientError as e:
            return e.response['Error']['Message']


    def sign_up(self, email, phone_number):
        try:
            response = self._client.sign_up(
                ClientId=self._client_id,
                SecretHash=self.__get_secret_hash(email),
                Username=email,
                Password=self.generate_random_password(),
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'phone_number', 'Value': phone_number}  # Include phone number
                ]
            )
            return response
        except ClientError as e:
            return e.response['Error']['Message']


    def __check_current_user(self, access_token):
        try:
            response = self._client.get_user(
                AccessToken=access_token
            )
            print('Current authenticated user:', response['Username'])
            return response
        except ClientError as e:
            print(f'Error: {e}')
            return None


    def respond_to_challenge(self, username, answer, session_auth):
        response = self._client.respond_to_auth_challenge(
            ClientId=self._client_id,
            ChallengeName='CUSTOM_CHALLENGE',
            Session=session_auth,
            ChallengeResponses={
                'USERNAME': username,  # Ensure 'USERNAME' is included
                'ANSWER': str(answer),
                'SECRET_HASH': self.__get_secret_hash(username)
            }
        )
        # Check if the user is authenticated
        if 'AuthenticationResult' in response:
            print('User is authenticated')
            access_token = response['AuthenticationResult']['AccessToken']
            return self.__check_current_user(access_token)
        else:
            print('User is not yet authenticated')
            return response
