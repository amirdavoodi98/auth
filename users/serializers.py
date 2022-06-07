from .models import User
from django_grpc_framework import proto_serializers
from protos import user_pb2 


class UserProtoSerializer(proto_serializers.ModelProtoSerializer):
    class Meta:
        model = User
        proto_class = user_pb2.User
        fields = ['id', 'username', 'user_type', 'mobile_number', 'password']