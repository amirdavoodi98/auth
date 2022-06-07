from importlib.metadata import metadata
import grpc
from protos import user_pb2, user_pb2_grpc, auth_pb2, auth_pb2_grpc, authorization_pb2, authorization_pb2_grpc
token = ""
with grpc.insecure_channel('localhost:50051') as channel:
    stub = auth_pb2_grpc.AuthenticationStub(channel)
    response = stub.Login(auth_pb2.LoginRequest(username="customer4", password="test"))
    token = response.token
    (print(response))

# with grpc.insecure_channel('localhost:50051') as channel:
#     stub = authorization_pb2_grpc.AuthorizationStub(channel)
#     metadata = (('access_token', token),)
#     response = stub.isEmployee(authorization_pb2.AuthorizationRequest(), metadata=metadata)
#     print(response)



# with grpc.insecure_channel('localhost:50051') as channel:
#     stub = user_pb2_grpc.UserControllerStub(channel)
#     response = stub.Create(user_pb2.User(username="test_branchManager", password="test", user_type="Branch_Manager", mobile_number="123456789"))
#     print (response)
#     response = stub.Create(user_pb2.User(username="test_bankManager", password="test", user_type="Bank_Manager", mobile_number="123456788"))
#     print (response)
