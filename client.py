import grpc
import asyncio
from protos.auth_pb2_grpc import AuthStub
from authenticator import Authenticator


async def start():
    async with grpc.aio.insecure_channel('localhost:50051') as channel:
        stub = AuthStub(channel)
        authenticator = Authenticator(stub.Authorize)
        token = await authenticator.run('testuser', 'testpassword')
        print(token)


asyncio.run(start())