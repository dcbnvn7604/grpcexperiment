from queue import Queue
import srp
from protos.auth_pb2 import AuthRequest


class Authorizer(object):
    def __init__(self, bidirect_authorize):
        self.bidirect_authorize = bidirect_authorize
        self.request_queue = Queue()

    def __iter__(self):
        return self
    
    def __next__(self):
        request = self.request_queue.get()
        if isinstance(request, AuthRequest):
            return request
        else:
            raise StopIteration()
    
    def run(self, user_name, password):
        usr = srp.User(user_name, password)
        uname, A = usr.start_authentication()
        self.request_queue.put(AuthRequest(phase1=AuthRequest.Phase1(
            uname=uname,
            A=A
        )))
        for response in self.bidirect_authorize(self):
            phase = response.WhichOneof('body')
            if phase == 'phase1':
                M = usr.process_challenge(response.phase1.s, response.phase1.B)
                if M is None:
                    raise Exception('process_challenge fail')
                self.request_queue.put(AuthRequest(phase2=AuthRequest.Phase2(M=M)))
            elif phase == 'phase2':
                usr.verify_session(response.phase2.HAMK)
                if not usr.authenticated():
                    raise Exception('authenticated fail')
                self.request_queue.put(AuthRequest(phase3=AuthRequest.Phase3()))
            elif phase == 'phase3':
                self.request_queue.put(None)
                token = response.phase3.token
            else:
                raise Exception('type of body unsupported')
        return token
