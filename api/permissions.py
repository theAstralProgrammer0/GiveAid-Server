from rest_framework import permissions


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users to access the view.

    This permission class checks if the requesting user is authenticated and 
    is considered an admin (staff). Admin users have elevated privileges in 
    the system and can access views that are restricted to them.

    Methods:
        has_permission(request, view): Checks if the requesting user has permission to access the view.

    Attributes:
        message (str): Optional message to be displayed when permission is denied.
    """
    def has_permission(self, request, view):
        # Allow access if the user is authenticated and is an admin (staff)
        return request.user and request.user.is_authenticated and request.user.is_staff