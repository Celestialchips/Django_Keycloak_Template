import jwt


class Authenticator:
    # Keys for testing only
    JWT_PKI_PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
    # KEEP THIS PRIVATE ADD YOUR RSA PRIVATE KEY HERE FOR TESTING
-----END RSA PRIVATE KEY-----"""

    JWT_PKI_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
ADD YOUR RSA PUBLIC KEY HERE FOR TESTING
-----END PUBLIC KEY-----"""

    def authenticate_token(self, token):
        return jwt.decode(
            token, self.JWT_PKI_PUBLIC_KEY, algorithms='RS256')

    def encode(self, payload):
        return jwt.encode(payload, self.JWT_PKI_PRIVATE_KEY, algorithm='RS256')