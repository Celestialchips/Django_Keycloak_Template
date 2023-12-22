from rest_framework import permissions
from dka.util import parse_tenant

class TenantPermission(permissions.BasePermission):
    """
    Permit tenants based on client roles in authentication claims.
    
    This permission class checks if the JWT token in the request has the necessary client_role
    to access the tenant specified in the X-Tenant-Id header. The mapping of HTTP methods to
    role actions (read, write, delete) is defined in the role_method_map method, which can be
    customized as needed.
    """
    def has_permission(self, request, view):
        tenant = parse_tenant(request)
        if tenant is None:
            return False

        for pair in request.auth.get('client_role', []):
            i_tenant, i_action = pair.split('/')
            if tenant == i_tenant and self.role_method_map(request.method) == i_action:
                return True

        return False

    def role_method_map(self, method):
        """
        Map HTTP methods to role actions. This can be modified to suit different
        HTTP method to action mappings.
        """
        if method in permissions.SAFE_METHODS:
            return 'read'
        elif method == 'DELETE':
            return 'delete'
        else:
            return 'write'
