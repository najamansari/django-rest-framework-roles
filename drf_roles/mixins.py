from django.conf import settings
from django.contrib.auth.models import Group, Permission

# Default settings
DEFAULT_GROUPS = [group.name.lower() for group in Group.objects.all()]
DEFAULT_PERMISSIONS = [
    permission.codename.lower() for permission in Permission.objects.all()
]

DEFAULT_REGISTRY = (
    "get_queryset",
    "get_serializer_class",
    "perform_create",
    "perform_update",
    "perform_destroy",
)

class RoleError(Exception):
    """Base class for exceptions in this module."""
    pass


class RoleViewSetMixin(object):
    """A ViewSet mixin that parameterizes DRF methods over roles"""
    _viewset_method_registry = set(getattr(settings, "VIEWSET_METHOD_REGISTRY", DEFAULT_REGISTRY))
    _role_groups = set(getattr(settings, "ROLE_GROUPS", DEFAULT_GROUPS))

    def _call_role_fn(self, fn, *args, **kwargs):
        """Attempts to call a role-scoped method"""
        try:
            role_name = self._get_role(self.request.user)
            role_fn = "{}_for_{}".format(fn, role_name)
            return getattr(self, role_fn)(*args, **kwargs)
        except (AttributeError, RoleError):
            return getattr(super(RoleViewSetMixin, self), fn)(*args, **kwargs)

    def _get_role(self, user):
        """Retrieves the given user's role"""
        user_groups = set([group.name.lower() for group in user.groups.all()])
        user_role = self._role_groups.intersection(user_groups)

        if len(user_role) < 1:
            raise RoleError("The user is not a member of any role groups")
        elif len(user_role) > 1:
            raise RoleError("The user is a member of multiple role groups")
        else:
            return user_role.pop()


class PermissionViewSetMixin(object):
    """A ViewSet mixin that parameterizes DRF methods over permissions."""
    _viewset_method_registry = set(getattr(settings, "VIEWSET_METHOD_REGISTRY", DEFAULT_REGISTRY))
    _permissions = DEFAULT_PERMISSIONS

    def __init__(self, *args, **kwargs):
        for permission in self._permissions:
            for fn in self._viewset_method_registry:
                register_permission_fn(permission, fn)

    def _call_permission_fn(self, fn, permission, *args, **kwargs):
        """Attempts to call a permission-scoped method"""
        try:
            if not self.request.user.has_perm(permission):
                raise RoleError("The user does not have the required permission")
            permission_fn = "{}_for_{}".format(fn, permission)
            return getattr(self, permission_fn)(*args, **kwargs)
        except (AttributeError, RoleError):
            return getattr(super(PermissionViewSetMixin, self), fn)(*args, **kwargs)


def register_permission_fn(permission, fn):
    """Dynamically adds fn to PermissionViewSetMixin.
    """
    def inner(self, *args, **kwargs):
        return self._call_permission_fn(fn, permission, *args, **kwargs)
    setattr(PermissionViewSetMixin, fn, inner)


def register_fn(fn):
    """Dynamically adds fn to RoleViewSetMixin"""
    def inner(self, *args, **kwargs):
        return self._call_role_fn(fn, *args, **kwargs)
    setattr(RoleViewSetMixin, fn, inner)

# Registers whitelist of ViewSet fns to override
for fn in RoleViewSetMixin._viewset_method_registry:
    register_fn(fn)
