import zmq
import sys
from consts import ZMQ_PUBSUB_KV6_JOURNEY

# Initialize a zeromq CONTEXT
context = zmq.Context()

sys.stderr.write('Setting up a ZeroMQ PUB: %s\n' % (ZMQ_PUBSUB_KV6_JOURNEY))
kv6journey = context.socket(zmq.SUB)
kv6journey.connect(ZMQ_PUBSUB_KV6_JOURNEY)
kv6journey.setsockopt(zmq.SUBSCRIBE, '')

# Set up a poller
poller = zmq.Poller()
poller.register(kv6journey, zmq.POLLIN)

while True:
    socks = dict(poller.poll())

    if socks.get(kv6journey) == zmq.POLLIN:
        node, result = kv6journey.recv_multipart()
        
        print node, result
