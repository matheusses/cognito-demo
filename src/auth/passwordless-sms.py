from authentication_cognito_service import AuthenticationCognitoService


auth = AuthenticationCognitoService()

username = input("username: ")
email = input("email: ")
phone_number = input("phone number: ")
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
auth.create_user(username, email)

signup_response = auth.sign_up(username, password, email, phone_number, access)
print("Sign-Up Response: ", signup_response)

# code_signup = input("Enter the code sent to your email: ")
# confirm_user_signup(username, code_signup)

# Step 2: Initiate auth
session = auth.initiate_auth(username)

# Simulate the user receiving the code and entering it
# Replace '123456' with the actual code sent via SMS
code = input("Enter the code sent via SMS: ")

# Step 3: Respond to the challenge
challenge_response = auth.respond_to_challenge(username, code, session)
