import pyotp


def generate_otp_secret():
    return pyotp.random_base32()


def generate_otp(secret):
    return pyotp.TOTP(secret).now()


def verify_otp(secret, otp):
    if not secret or not otp:
        return False
    return pyotp.TOTP(secret).verify(str(otp).strip(), valid_window=1)
