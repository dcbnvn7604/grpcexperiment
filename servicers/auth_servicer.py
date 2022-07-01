from cmath import phase
import srp

from protos.auth_pb2_grpc import AuthServicer as ProtoAuthServicer
from protos.auth_pb2 import AuthResponse

salt = 'ac39de43'
vkey = '3244ff8b2a806a821993814ff3883ba8db5baa1a71974fbb201318eaf8f0d5a972a5ca66383bb88b112cbcb5bce79816a107a6f0df192cf083f69a4db3d949c0e772f98f13a1ba76caff28f7bfd1ade61d376f5137fab4ab1c457fb5c571e0919e95f0988835a9cab671eceaaad35ef6a822f04f4cc776cde07cbdea18d864b6687ebc9e6b47c0b297040a51fdb41f9381fb4a4dc27f11cec0c5ccf25c9f60f482e3519be3447f9bf20924166b36905eb4e2a3ba221ac73242b7ace1e0dad8056ee0fca598dfa92f0a4b8a00b4236a78fc743b08c0685ab3cd22caa3092c03d0e16b969858a092b76965187daecc1e2965c29d3e8021375ae56f503a9f5e60b5'

class AuthServicer(ProtoAuthServicer):
    async def Authorize(self, request_iterator, context):
        print('start authorize')
        for request in request_iterator:
            phase = request.WhichOneof('body')
            if phase == 'phase1':
                print('start phase1')
                svr = srp.Verifier(request.phase1.uname, bytes.fromhex(salt), bytes.fromhex(vkey), request.phase1.A)
                s,B =svr.get_challenge()
                if s is None or B is None:
                    raise Exception('get_challenge fail')
                yield AuthResponse(phase1=AuthResponse.Phase1(s=s,B=B))
            elif phase == 'phase2':
                print('start phase2')
                HAMK = svr.verify_session(request.phase2.M)
                if HAMK is None:
                    raise Exception('verify_session fail')
                yield AuthResponse(phase2=AuthResponse.Phase2(HAMK=HAMK))
            elif phase == 'phase3':
                print('start phase3')
                if not svr.authenticated():
                    raise Exception('authenticated fail')
                yield AuthResponse(phase3=AuthResponse.Phase3(token='token'))
            else:
                raise Exception('type of body unsupported')
        print('end authorize')
