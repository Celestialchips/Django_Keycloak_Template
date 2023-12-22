import django.db.utils
from django.test import TestCase
from django.contrib.auth.models import User
from django_keycloak_auth import settings

from dka.auth.backend import JWTAuth

import django.http
import datetime
import jwt
import os


class RootTestCase(TestCase):
    """
        Root test case with utility methods for creating JWTs and setting request options.
        Can be extended for different types of JWT-based authentication testing.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def default_client_opts(self, **kwargs):
        # Make JWT with the given client role claims, defaulting to tenant
        token = make_jwt(client_role=kwargs.get(
            'client_role', ['tenant/write', 'tenant/read']))

        return {
            'HTTP_AUTHORIZATION': 'Bearer: {}'.format(token),
            'HTTP_X_TENANT_ID': 'tenant'
        }
    
    def create_test_user(self, username, password="test_password"):
        """
        Utility method to create a test user.
        """
        return User.objects.create_user(username=username, password=password)

    def client_opts(self, **kwargs):
        opts = self.default_client_opts(**kwargs)
        opts.update(**kwargs)
        return opts


def make_jwt(**kwargs):
    """
    Create a JWT with given parameters. 
    Default values are taken from environment variables or set to sensible defaults.
    """
    current_time = datetime.datetime.utcnow()

    # Ensure mandatory claims like 'email' are included
    if 'email' not in kwargs:
        raise ValueError("Email is a required claim for JWT")

    params = {
        'iat': current_time,
        'exp': current_time + datetime.timedelta(minutes=30),  # Adjust expiry time if needed
        'nbf': current_time,
        'jti': kwargs.get('jti', ''),
        'iss': kwargs.get('iss', os.environ.get('JWT_ISSUER', 'default_issuer')),
        'sub': kwargs.get('sub', ''),
        'typ': 'Bearer',
        'azp': 'tenant-frontend',
        'nonce': '',
        'session_state': '',
        'acr': '1',
        'scope': 'openid',
        'groups': [],
        'email': kwargs.get('email', ''),
        'client_role': kwargs.get('client_role', [])
    }

    secret = os.environ.get('JWT_SECRET', 'default_secret')
    return jwt.encode(params, secret, algorithm='HS256').decode('utf-8')

class JWTAuthTestCase(RootTestCase):
    def test_auth_jwt_no_cookie(self):
        req = django.http.HttpRequest()
        settings.JWT_COOKIE = 'jwt_token'
        settings.JWT_SECRET = 'secret'
        req.COOKIES = {'jwt': 'abc'}
        j = JWTAuth()
        self.assertEqual(j.authenticate(req), None)

    def test_auth_jwt_invalid(self):
        req = django.http.HttpRequest()
        req.headers = {'Authorization': 'Bearer: abc'}
        j = JWTAuth()
        self.assertEqual(j.authenticate(req), None)

    def test_auth_jwt_valid_new_user(self):
        valid_token = make_jwt(**{'email': 'user@example.com'})

        req = django.http.HttpRequest()
        req.headers = {'Authorization': f'Bearer: {valid_token}'}
        j = JWTAuth()

        authenticated_user, _ = j.authenticate(req)
        self.assertEqual(authenticated_user.username,
                         'user@example.com')

    def test_auth_jwt_valid_existing_user(self):
        User.objects.create(username='existing@example.com')
        valid_token = make_jwt(**{'email': 'existing@example.com'})

        req = django.http.HttpRequest()
        req.headers = {'Authorization': f'Bearer: {valid_token}'}
        j = JWTAuth()

        authenticated_user, _ = j.authenticate(req)
        self.assertEqual(authenticated_user.username,
                         'existing@example.com')
