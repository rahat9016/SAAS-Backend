class AuthMessages:
    """Authentication-related messages"""

    # User related
    USER_NOT_FOUND = "User not found."
    USER_ALREADY_EXISTS = "User with this email already exists."
    PHONE_ALREADY_EXISTS = "User with this phone already exists."
    ACCOUNT_NOT_ACTIVE = "This account is not active. Please activate first."
    ACCOUNT_ACTIVATED = "Your account has been verified."

    # Authentication related
    INVALID_CREDENTIALS = "Invalid email or password."
    INCORRECT_OLD_PASSWORD = "Incorrect old password."

    # Token related
    TOKEN_INVALID = "Invalid or expired token."
    TOKEN_EXPIRED = "Refresh token has expired."
    TOKEN_REFRESHED = "Token refreshed successfully."

    # OTP related
    OTP_SENT = "A new OTP has been sent successfully."
    OTP_VERIFIED = "OTP verified successfully."
    OTP_INVALID = "Invalid or expired OTP."
    OTP_RESEND_LIMIT = (
        "Please wait for {wait_time} seconds before requesting another OTP."
    )

    # Registration related
    REGISTRATION_SUCCESS = (
        "User created successfully. Please check your email to activate your account."
    )
    REGISTRATION_FAILED = "User registration failed."

    # Login related
    LOGIN_SUCCESS = "Login successful."
    LOGIN_FAILED = "Login failed."

    # Password related
    PASSWORD_CHANGED = "Password changed successfully."
    PASSWORD_CHANGE_FAILED = "Change password failed."

    # Google sign-in
    GOOGLE_SIGNIN_SUCCESS = "Google sign-in successful."
    GOOGLE_SIGNIN_FAILED = "Google sign-in failed."
    EMAIL_NOT_FOUND_IN_TOKEN = "Email not found in Google token."

    # General
    SOMETHING_WENT_WRONG = "Something went wrong."


class ProfileMessages:
    """Profile-related messages"""

    PROFILE_UPDATED = "Profile updated successfully."
    PROFILE_RETRIEVED = "Profile retrieved successfully."
    PROFILE_NOT_FOUND = "Profile not found."


class CommonMessages:
    """Common messages used across the app"""

    SUCCESS = "Operation successful."
    FAILED = "Operation failed."
    NOT_FOUND = "Resource not found."
    UNAUTHORIZED = "Authentication required."
    FORBIDDEN = "Permission denied."
    VALIDATION_ERROR = "Validation failed."
