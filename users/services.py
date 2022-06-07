from django_grpc_framework import generics
import jwt
import grpc
import datetime
from rest_framework_simplejwt.views import TokenObtainPairView


from .models import User
from .serializers import UserProtoSerializer
from .authenticate import IsAuthenticated, IsAdmin, IsBankMnager, IsBranchManager, IsCustomer, IsEmployee
from protos import auth_pb2, authorization_pb2
from auth.settings import TOKEN_EXPIRATION, JWT_SECRET

def generate_token(user):
    user_info = {'username': user.username,
                 'email': None,
                 'is_superuser': user.is_superuser,
                 'user_id': user.id
                 }
    return jwt.encode({'user_info': user_info,
                       'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRATION)
                       }, JWT_SECRET, algorithm='HS256')


class UserService(generics.ModelService):
    """
    gRPC service that allows users to be retrieved or updated.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserProtoSerializer
    # permission_class = (IsAuthenticated,)

    def perform_create(self, serializer):
        """Save a new object instance."""
        serializer.save()
        user = User.objects.get(id=serializer.instance.id)
        user.set_password(serializer.data['password'])
        user.save()

class LoginService(generics.ModelService, TokenObtainPairView):

    def Login(self, request, context):
        try:
            from google.protobuf import message
            response = auth_pb2.LoginResponse()
            username = request.username
            password = request.password
            user = User.objects.get(username=username)
            valid = user.check_password(password)
            if valid:
                token = generate_token(user)
                response.token = token
            else:
                response.status = grpc.StatusCode.UNAUTHENTICATED
            return response
        except Exception as e:
            return grpc.StatusCode.UNAUTHENTICATED

class AuthorizationService(generics.ModelService):

    def isAdmin(self, request, context):
        response = authorization_pb2.AuthorizationResponse()
        metadata = dict(context.invocation_metadata())
        response.resp = -1
        print(response)
        user_token = str(metadata['access_token'])
        access_token = jwt.decode(user_token, options={"verify_signature": False})
        userID = access_token['user_info']['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'ADMIN':
            response.resp = 1
            return response
        return response
    
    def IsBankMnager(self, request, context):
        response = authorization_pb2.AuthorizationResponse()
        metadata = dict(context.invocation_metadata())
        response.resp = -1
        user_token = str(metadata['access_token'])
        access_token = jwt.decode(user_token, options={"verify_signature": False})
        userID = access_token['user_info']['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Bank_Manager':
            response.resp = 1
            return response
        return response

    def isBranchManager(self, request, context):
        response = authorization_pb2.AuthorizationResponse()
        metadata = dict(context.invocation_metadata())
        response.resp = -1
        user_token = str(metadata['access_token'])
        access_token = jwt.decode(user_token, options={"verify_signature": False})
        userID = access_token['user_info']['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Branch_Manager':
            response.resp = 1
            return response
        return response

    def isEmployee(self, request, context):
        response = authorization_pb2.AuthorizationResponse()
        metadata = dict(context.invocation_metadata())
        response.resp = -1
        user_token = str(metadata['access_token'])
        access_token = jwt.decode(user_token, options={"verify_signature": False})
        userID = access_token['user_info']['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Employee':
            response.resp = 1
            return response
        return response

    def isCustomer(self, request, context):
        response = authorization_pb2.AuthorizationResponse()
        metadata = dict(context.invocation_metadata())
        response.resp = -1
        user_token = str(metadata['access_token'])
        access_token = jwt.decode(user_token, options={"verify_signature": False})
        userID = access_token['user_info']['user_id']
        user = User.objects.get(id=userID)
        if user.user_type == 'Customer':
            response.resp = 1
            return response
        return response