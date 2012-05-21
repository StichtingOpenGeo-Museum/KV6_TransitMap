#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2010  Nathanael C. Fritz
    This file is part of SleekXMPP.

    See the file LICENSE for copying permission.
"""

import sys
import logging
import time
from optparse import OptionParser
import zmq
import simplejson as serializer
from rdwgs84 import rdwgs84
from xml.etree import cElementTree as ET

import sleekxmpp
from sleekxmpp.componentxmpp import ComponentXMPP
from sleekxmpp.exceptions import XMPPError
from sleekxmpp.plugins.xep_0060.stanza.pubsub_event import EventItems, EventItem
from sleekxmpp.plugins.xep_0060.stanza.pubsub import Subscriptions

from secret import component_server, component_port, component_jid, component_password
from consts import ZMQ_PUBSUB_KV6_JOURNEY

# Python versions before 3.0 do not use UTF-8 encoding
# by default. To ensure that Unicode is handled properly
# throughout SleekXMPP, we will set the default encoding
# ourselves to UTF-8.
if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input


class PubsubComponent(ComponentXMPP):

    """
    A simple SleekXMPP component that echoes messages.
    """

    def __init__(self, jid, secret, server, port):
        ComponentXMPP.__init__(self, jid, secret, server, port)

        self.use_signals()

        # The session_start event will be triggered when
        # the bot establishes its connection with the server
        # and the XML streams are ready for use. We want to
        # listen for this event so that we we can intialize
        # our roster.
        self.add_event_handler("session_start", self.start)
        
        self.add_event_handler("pubsub_subscribe", self._pubsub_subscribe)
        self.add_event_handler("pubsub_unsubscribe", self._pubsub_unsubscribe)
        self.add_event_handler("pubsub_retrieve_subscriptions", self._pubsub_retrieve_subscriptions)
        self.add_event_handler("pubsub_retrieve_affiliations", self._pubsub_retrieve_affiliations)
        self.add_event_handler("pubsub_get_items", self._pubsub_get_items)

        self.add_event_handler("pubsub_set_items", self._pubsub_set_items)
        self.add_event_handler("pubsub_create_node", self._pubsub_create_node)
        self.add_event_handler("pubsub_delete_node", self._pubsub_delete_node)
        self.add_event_handler("pubsub_retract_node", self._pubsub_retract)
        self.add_event_handler("pubsub_get_config_node", self._pubsub_get_config_node)
        
        self.add_event_handler("presence_available", self._presence_available)
        self.add_event_handler("presence_subscribed", self._presence_subscribed)

        self.auto_authorize = True # Automatic bidirectional subscriptions
        self.auto_subscribe = True

        self.pnick = "openOV KV6 Journey"

        self.friends = set([])
        self.subscriptions = {}

    def _presence_available(self, presence):
        self.friends.add(presence['from'].bare)

    def _presence_subscribed(self, presence):
        self.friends.add(presence['from'].bare)

    def _pubsub_subscribe(self, iq):
        jid = iq['pubsub']['subscribe']['jid']
        node = iq['pubsub']['subscribe']['node']

        print jid, node

        if jid.bare not in self.friends:
            self.send_presence_subscription(pto=jid.bare, ptype='subscribe', pnick=self.pnick)
        
        if node not in self.subscriptions:
            self.subscriptions[node] = set([jid.full])
            kv6journey.setsockopt(zmq.SUBSCRIBE, node)
        else:
            self.subscriptions[node].append(jid.full)

        iq_reply = self.makeIqResult(id=iq['id'], ifrom=iq['to'], ito=iq['from'])
        return iq_reply.send(block=False)

    def _pubsub_unsubscribe(self, iq):
    	jid = iq['pubsub']['subscribe']['jid']
        node = iq['pubsub']['subscribe']['node']

        if node in self.subscriptions:
            self.subscriptions[node].remove(jid.full)
            if len(self.subscriptions[node]) == 0:
                kv6journey.setsockopt(zmq.UNSUBSCRIBE, node)
                del self.subscriptions[node]

        iq_reply = self.makeIqResult(id=iq['id'], ifrom=iq['to'], ito=iq['from'])
        return iq_reply.send(block=False)

    def _pubsub_retrieve_subscriptions(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _get_items(self, jid, node, data, disco, pubsub):
        raise XMPPError(condition='feature-not-implemented')

    def _disco_items_query(self, jid, node, data):
        raise XMPPError(condition='feature-not-implemented')
    
    def _pubsub_get_items(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _pubsub_retrieve_affiliations(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _pubsub_set_items(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _pubsub_create_node(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _pubsub_delete_node(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _pubsub_retract(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def _pubsub_get_config_node(self, iq):
        raise XMPPError(condition='feature-not-implemented')

    def start(self, event):
        return


if __name__ == '__main__':
    # Setup the command line arguments.
    optp = OptionParser()

    # Output verbosity options.
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')

    # Setup the PubsubComponent and register plugins. Note that while plugins
    # may have interdependencies, the order in which you register them does
    # not matter.
    xmpp = PubsubComponent(component_jid, component_password, component_server, component_port)
    xmpp.registerPlugin('xep_0030') # Service Discovery
    xmpp.registerPlugin('xep_0060') # PubSub
    xmpp.registerPlugin('xep_0080') # Location

    # Connect to the XMPP server and start processing XMPP stanzas.
    if xmpp.connect():
        xmpp.process(threaded=True)
        print("Done")
    else:
        print("Unable to connect.")

    # Initialize a zeromq CONTEXT
    context = zmq.Context()

    sys.stderr.write('Setting up a ZeroMQ PUB: %s\n' % (ZMQ_PUBSUB_KV6_JOURNEY))
    kv6journey = context.socket(zmq.SUB)
    kv6journey.connect(ZMQ_PUBSUB_KV6_JOURNEY)

    # Set up a poller
    poller = zmq.Poller()
    poller.register(kv6journey, zmq.POLLIN)

    while True:
        socks = dict(poller.poll())

        if socks.get(kv6journey) == zmq.POLLIN:
            node, result = kv6journey.recv_multipart()

            subscriptions = set([])

            if node in xmpp.subscriptions:
                subscriptions.add(node)

            subscriptions = subscriptions.union(set(filter(lambda s: node.startswith(s), xmpp.subscriptions.keys())))

            if len(subscriptions) > 0:
                result = serializer.loads(result)
                print result
                if 'rd_x' not in result:
                    continue

                if 'description' in result:
                    extra = '<description>%(description)s</description><locality>%(locality)s</locality><timestamp>%(timestamp)s</timestamp>' % result
                else:
                    extra = '<timestamp>%(timestamp)s</timestamp>' % result
                
                normal = '<lon>%f</lon><lat>%f</lat>' % rdwgs84(result['rd_x'], result['rd_y'])
                
                items = EventItems() 
                items['node'] = node
                item = EventItem()
                item['id'] = '%(dataownercode)s_%(vehiclenumber)s' % result
                item['payload'] = ET.XML('<geoloc xmlns="http://jabber.org/protocol/geoloc">'+normal+extra+'</geoloc>')
                items.append(item)

                msg = xmpp.Message()
                msg['id'] = 'kv6_update0'
                msg['from'] = xmpp.boundjid.bare
                msg['pubsub_event'].append(items)

                for subscription in subscriptions:
                    for jid in xmpp.subscriptions[subscription]:
                        msg['to'] = jid
                        msg.send()
            else:
                kv6journey.setsockopt(zmq.UNSUBSCRIBE, node)
