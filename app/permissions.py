# from django.conf import settings
from rest_framework import permissions
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from app.models import User
# import jwt

class IsAuthenticatedAllowSafeMethod(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return request.user.is_authenticated

class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return obj.owner == request.user

# class IsUserOrReadOnly(permissions.BasePermission):
#     def has_permission(self, request, view):
#         if request.method in permissions.SAFE_METHODS:
#             return True
#         return request.user.is_authenticated
#

#
#
# class IsMineOrNothing(permissions.BasePermission):
#     def has_object_permission(self, request, view, obj):
#         if request.user.is_staff:
#             return True
#         return obj.username == request.user.username
