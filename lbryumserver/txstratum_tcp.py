from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineOnlyReceiver
from decimal import Decimal
import json

from lbryumserver.processor import Session
from lbryumserver.utils import logger


class StratumProtocol(LineOnlyReceiver):
    delimiter = b'\n'

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher

    def connectionMade(self):
        session = Session(self.dispatcher)
        session.address = self.transport.getPeer()
        session.name = "TCP"
        session.timeout = 1000
        session.send_response = lambda response: self.sendResponse(response)
        self.dispatcher.add_session(session)
        self.session = session

    def sendResponse(self, data):
        def default_decimal(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            raise TypeError

        try:
            msg = json.dumps(data, default=default_decimal)
        except BaseException as e:
            logger.error('send_response:' + str(e))
            return
        self.sendLine(msg)

    def lineReceived(self, line):
        try:
            command = json.loads(line)
        except:
            self.sendResponse({"error": "bad JSON"})
            return True
        try:
            # Try to load vital fields, and return an error if
            # unsuccessful.
            message_id = command['id']
            method = command['method']
        except:
            # Return an error JSON in response.
            self.sendResponse({"error": "syntax error", "request": line})
        else:
            # print_log("new request", command)
            if True or 'subscribe' in method:
                self.dispatcher.do_dispatch(self.session, command)
            else: # alternative path of calling the command directly, turned out to block the reactor
                prefix = method.split('.')[0]
                processor = self.dispatcher.processors[prefix]
                result = processor.process(command)
                self.sendResponse({'id': message_id, 'result': result})


class StratumProtocolFactory(Factory):

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher.request_dispatcher

    def buildProtocol(self, addr):
        return StratumProtocol(self.dispatcher)
