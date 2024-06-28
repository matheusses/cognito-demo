from authentication_cognito_service import AuthenticationCognitoService


auth = AuthenticationCognitoService()

email = input("email: ")
phone_number = input("phone number: ")
uuid = input("uuid: ")
company_id = input("company id: ")
role = input("role: ")
access = {
    "companies": [
        {
            "id": company_id,
            "role": role
        }
    ]
}
password = auth.generate_random_password()

#Step 1: Create the user
signup_response = auth.sign_up(email, phone_number)
user_name = auth.get_username_by_phone_number(phone_number)
auth.update_user(user_name, uuid, access)
auth.update_set_user_password(user_name)

# Step 2: Initiate auth
session = auth.initiate_auth(user_name)

# Simulate the user receiving the code and entering it
# Replace '123456' with the actual code sent via SMS
code = input("Enter the code sent via SMS: ")

# Step 3: Respond to the challenge
challenge_response = auth.respond_to_challenge(user_name, code, session)
