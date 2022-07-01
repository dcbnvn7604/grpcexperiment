import asyncio
import grpc
from protos.auth_pb2_grpc import add_AuthServicer_to_server
from servicers.auth_servicer import AuthServicer


async def start():
    server = grpc.aio.server()
    add_AuthServicer_to_server(AuthServicer(), server)
    server.add_insecure_port('[::]:50051')
    await server.start()
    await server.wait_for_termination()


asyncio.run(start())