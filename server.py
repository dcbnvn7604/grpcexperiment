from concurrent import futures
import grpc
from protos.auth_pb2_grpc import add_AuthServicer_to_server
from servicers.auth_servicer import AuthServicer


def start():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_AuthServicer_to_server(AuthServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

start()
