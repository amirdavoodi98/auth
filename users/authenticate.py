import grpc
import jwt
from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.tokens import AccessToken

from auth.settings import JWT_SECRET
from .models import User


ACCESS_TOKEN_ERROR_MSG = 'Invalid access_token'
SESSION_TOKEN_ERROR_MSG = 'Invalid session_token'
SESSION_TOKEN_EXPIRED_MSG = 'Expired session_token'
PERMISSION_EXPIRED_MSG = 'Endpoint is restricted access'


# def get_user_info_from_context(context, jwt_key):
#     metadata = dict(context.invocation_metadata())
#     session_token = metadata['session_token']
#     user_info = jwt.decode(session_token, key=jwt_key).get('user_info')
#     return user_info



class IsAuthenticated(BasePermission):

    # def __init__(self, response_class=None, jwt_key=None, permission_admin=False):
    #     print('.' * 100)
    #     JWT_SECRET = jwt_key
    #     self.response_class = response_class
    #     self.permission_admin = permission_admin
    #     print('.' * 100)
    #     # return self.do_authentication()
    def __init__(self):
        print('>> Called :)')

    def __call__(self, func):
        def session(instance, request, context):
            success, error_handler = self.has_permission(request, context)
            if not success:
                return error_handler
            return func(instance, request, context)

        return session

    def has_permission(self, request, context):
        print(context)
        metadata = dict(context.invocation_metadata())
        print(metadata)
        access_token = metadata['access_token']
        if self.has_access_token_error(access_token):
            return False
        has_error, detail = self.has_jwt_error(access_token)
        if has_error:
            return False
        return True

    @staticmethod
    def has_access_token_error(access_token):
        return not access_token

    def has_jwt_error(self, access_token):
        if JWT_SECRET:
            try:
                jwt.decode(access_token,
                           key=JWT_SECRET,
                           algorithms=["HS256"]).get('user_info')
            except jwt.DecodeError:
                return True, SESSION_TOKEN_ERROR_MSG
            except jwt.ExpiredSignatureError:
                return True, SESSION_TOKEN_EXPIRED_MSG
            # if self.permission_admin and not user_info.get('is_superuser'):
            #     return True, PERMISSION_EXPIRED_MSG
        return False, None

    # def invalidate(self, context, details):
    #     context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
    #     context.set_details(details)
    #     return self.response_class()




class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        user_token = str(request.headers.get('Authorization')).split(' ')[1]
        access_token = AccessToken(user_token)
        userID = access_token['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'ADMIN':
            return True
        return False

class IsBankMnager(BasePermission):
    def has_permission(self, request, view):
        user_token = str(request.headers.get('Authorization')).split(' ')[1]
        access_token = AccessToken(user_token)
        userID = access_token['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Bank_Manager':
            return True
        return False

class IsBranchManager(BasePermission):
    def has_permission(self, request, view):
        user_token = str(request.headers.get('Authorization')).split(' ')[1]
        access_token = AccessToken(user_token)
        userID = access_token['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Branch_Manager':
            return True
        return False

class IsEmployee(BasePermission):
    def has_permission(self, request, view):
        user_token = str(request.headers.get('Authorization')).split(' ')[1]
        access_token = AccessToken(user_token)
        userID = access_token['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Employee':
            return True
        return False

class IsCustomer(BasePermission):
    def has_permission(self, request, view):
        user_token = str(request.headers.get('Authorization')).split(' ')[1]
        access_token = AccessToken(user_token)
        userID = access_token['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Customer':
            return True
        return False