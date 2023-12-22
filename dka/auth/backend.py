import logging
import importlib
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django_keycloak_auth import settings
import jwt
from rest_framework.authentication import BaseAuthentication


# Logger setup
logger = logging.getLogger(__name__)


# Constants
HTTP_AUTHORIZATION = 'Authorization'
X_FORWARDED_ACCESS_TOKEN = 'X-Forwarded-Access-Token'


# Dynamic import of authenticator module
authlib = importlib.import_module(settings.JWT_AUTHENTICATOR)
authenticator = authlib.Authenticator()


class JWTAuthenticator:
    """
    Authenticates and returns JWTs from authorization headers, creating the user if the token validates.
    """
    def validate_request(self, request):
        token = self.find_token(request)
        if token is None:
            return None

        try:
            token = authenticator.authenticate_token(token)
        except jwt.ExpiredSignatureError:
            logger.error("Token expired")
            return None
        except (jwt.DecodeError, jwt.InvalidSignatureError, jwt.InvalidTokenError) as e:
            logger.error(f"Token invalid: {e}")
            return None

        return self.get_or_create_user(token)

    def find_token(self, request):
        """
        Tries to find a bearer token via Authorization header, then tries x-forwarded-access-token.
        """
        token = request.headers.get(HTTP_AUTHORIZATION)
        if token:
            return token.split(' ')[1]

        return request.headers.get(X_FORWARDED_ACCESS_TOKEN)

    def get_or_create_user(self, token):
        """
        Retrieves or creates a User based on the token information.
        """
        email = token.get('email')
        if not email:
            logger.error("Token does not contain email field")
            return None

        user, created = User.objects.get_or_create(username=email)
        return user, token


class JWTAuth(BaseAuthentication):
    """
    Implements JWT authentication for API.
    """
    auth = JWTAuthenticator()

    def authenticate(self, request):
        logger.info('Authenticating JWT')
        return self.auth.validate_request(request)


class AdminOIDCAuth(BaseBackend):
    """
    Implements JWT authentication for Admin.
    """
    auth = JWTAuthenticator()

    def authenticate(self, request):
        logger.info('Authenticating Admin OIDC')
        auth_status = self.auth.validate_request(request)
        if auth_status is None:
            return None

        user, token = auth_status
        try:
            if settings.ADMIN_ROLE in token['resource_access'][settings.OIDC_CLIENT_ID]['roles']:
                user.is_staff = True
                user.is_superuser = True
                user.save()
                return user
        except KeyError as e:
            logger.error(f"Error processing token for admin role: {e}")

        return None

