import simplejson as serializer
import zmq
import sys
from consts import ZMQ_PUBSUB_KV6, ZMQ_PUBSUB_KV6_JOURNEY
from kv1_querystops import querystops

"""
Typical KV6 message:

{
    'messagetype': 'ARRIVAL',
    'timestamp': '2012-05-12T16:07:33+02:00',
    'dataownercode': 'CXX',
    'rd_x': 136801,
    'rd_y': 456135,
    'source': 'VEHICLE',
    'lineplanningnumber': 'U011',
    'journeynumber': 4112,
    'reinforcementnumber': 0
    'vehiclenumber': 7855,
    'userstopcode': '50003370',
    'passagesequencenumber': 0,
    'operatingday': '2012-05-12',
    'punctuality': 33,
}
"""

stops = querystops()

# Initialize a zeromq CONTEXT
context = zmq.Context()
sys.stderr.write('Setting up a ZeroMQ SUB: %s\n' % (ZMQ_PUBSUB_KV6))
subscribe_kv6 = context.socket(zmq.SUB)
subscribe_kv6.connect(ZMQ_PUBSUB_KV6)
subscribe_kv6.setsockopt(zmq.SUBSCRIBE, '')

sys.stderr.write('Setting up a ZeroMQ PUB: %s\n' % (ZMQ_PUBSUB_KV6_JOURNEY))
publish_kv6 = context.socket(zmq.PUB)
publish_kv6.bind(ZMQ_PUBSUB_KV6_JOURNEY)

# Set up a poller
poller = zmq.Poller()
poller.register(subscribe_kv6, zmq.POLLIN)

while True:
    socks = dict(poller.poll())

    if socks.get(subscribe_kv6) == zmq.POLLIN:
        results = serializer.loads(subscribe_kv6.recv())
        for result in results:
            if result['messagetype'] in ['ONSTOP', 'DEPARTURE', 'ARRIVAL']:
                pointcode = result['dataownercode'] + '|' + result['userstopcode']
                if pointcode in stops:
                    result.update(stops[pointcode])

            envelope = 'KV6/' + '|'.join([result['dataownercode'], result['lineplanningnumber'], str(result['journeynumber']), str(result['reinforcementnumber']), result['operatingday']])
            publish_kv6.send_multipart([envelope, serializer.dumps(result)])
