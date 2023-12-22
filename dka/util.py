TENANT_KEY = 'X-Tenant-Id'  # Change this key as per the application requirements
DEFAULT_TENANT = 'auth'  # Default tenant can be configured as needed

def parse_tenant(request):
    """
    Parse the tenant from a request object.
    This can be customized to extract tenant information from different parts of the request.
    """
    return request.headers.get(TENANT_KEY, DEFAULT_TENANT)
