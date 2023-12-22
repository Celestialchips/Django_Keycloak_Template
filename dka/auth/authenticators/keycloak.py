from keycloak import KeycloakOpenID
from django_keycloak_auth import settings


client = KeycloakOpenID(server_url=settings.OIDC_SERVER_BASE_URL,
                        client_id=settings.OIDC_CLIENT_ID,
                        realm_name=settings.OIDC_REALM,
                        client_secret_key=settings.OIDC_CLIENT_SECRET,
                        verify=True)
certs = client.certs()


class Authenticator:
    """
    Keycloak token validator

    """
    options = {"verify_signature": True, "verify_aud": False, "exp": True}

    def authenticate_token(self, token):
        return client.decode_token(
            token, key=certs['keys'][0], options=self.options)
