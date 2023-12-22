from dka.auth.backend import AdminOIDCAuth
from django.core.exceptions import PermissionDenied
from django.contrib import auth


class AdminIdentityMiddleware:
    """
    Middleware for handling admin identity authentication.
    Authenticates admin users using OIDC and sets permissions accordingly.
    Can be adapted for different authentication mechanisms or admin identification logic.

    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Bypass for authenticated users
        if request.user.is_authenticated:
            return self.get_response(request)

        try:
            user = AdminOIDCAuth().authenticate(request)
        except Exception as e:
            # Log exception details here
            return self.handle_authentication_failure(request, e)

        # Authentication checks for admin paths
        if request.get_full_path().startswith('/admin'):
            if user is None:
                raise PermissionDenied()
            auth.login(request, user)

        return self.get_response(request)

    def handle_authentication_failure(self, request, exception):
        """
        Handle failures in authentication. This method can be customized to return
        different responses based on the type of exception or application logic.
        """
        # Custom logic for handling authentication failure
        # Example: log the exception, return a custom response, etc.
        # For now, just raising PermissionDenied
        raise PermissionDenied()