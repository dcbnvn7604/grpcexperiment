import grpc
from protos.auth_pb2_grpc import AuthStub
from authorizer import Authorizer

channel = grpc.insecure_channel('localhost:50051')
stub = AuthStub(channel)

authorizer = Authorizer(stub.Authorize)
token = authorizer.run('testuser', 'testpassword')
print(token)