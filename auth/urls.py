from django.contrib import admin
from django.urls import path, include

from protos import user_pb2_grpc, auth_pb2_grpc, authorization_pb2_grpc
from users.services import UserService, LoginService, AuthorizationService



urlpatterns = [
    path('admin/', admin.site.urls),
]


def grpc_handlers(server):
    user_pb2_grpc.add_UserControllerServicer_to_server(UserService.as_servicer(), server)
    auth_pb2_grpc.add_AuthenticationServicer_to_server(LoginService.as_servicer(), server)
    authorization_pb2_grpc.add_AuthorizationServicer_to_server(AuthorizationService.as_servicer(), server)