import srp
import asyncio
from protos.auth_pb2 import AuthRequest


class Authenticator(object):
    def __init__(self, bidirect_authenticate):
        self.bidirect_authenticate = bidirect_authenticate
        self.request_queue = asyncio.Queue()
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        request = await self.request_queue.get()
        if isinstance(request, AuthRequest):
            return request
        else:
            raise StopAsyncIteration ()
    
    async def run(self, user_name, password):
        usr = srp.User(user_name, password)
        uname, A = usr.start_authentication()
        await self.request_queue.put(AuthRequest(phase1=AuthRequest.Phase1(
            uname=uname,
            A=A
        )))
        async for response in self.bidirect_authenticate(self):
            phase = response.WhichOneof('body')
            if phase == 'phase1':
                M = usr.process_challenge(response.phase1.s, response.phase1.B)
                if M is None:
                    raise Exception('process_challenge fail')
                await self.request_queue.put(AuthRequest(phase2=AuthRequest.Phase2(M=M)))
            elif phase == 'phase2':
                usr.verify_session(response.phase2.HAMK)
                if not usr.authenticated():
                    raise Exception('authenticated fail')
                await self.request_queue.put(AuthRequest(phase3=AuthRequest.Phase3()))
            elif phase == 'phase3':
                await self.request_queue.put(None)
                token = response.phase3.token
            else:
                raise Exception('type of body unsupported')
        return token
