#!/bin/env python
import asyncio
from message import WeechatMessage
import argparse
import notify2
from os import path
import ssl
import subprocess


class WeechatRelayListener(asyncio.Protocol):
    def __init__(self, password, loop):
        self.password = password
        self.loop = loop
        self.buffer = b''
        self.notification = None
        notify2.init('weelisten')

    def connection_made(self, transport):
        transport.write('init password={},compression=on\n'.format(self.password).encode())
        transport.write('sync\n'.encode())

    def data_received(self, data):
        self.buffer += data
        while len(self.buffer) >= 4:
            length = int.from_bytes(self.buffer[:4], byteorder='big')
            if len(self.buffer) >= length:
                self.pop_message(length)

    def pop_message(self, expected_length):
        to_parse = self.buffer[:expected_length]
        self.buffer = self.buffer[expected_length:]
        self.parse_message(to_parse)

    def parse_message(self, message):
        wc = WeechatMessage(message)
        result = wc.get_hdata_result()
        if isinstance(result, dict) and result.get('tags_array'):
            highlight = bool.from_bytes(result['highlight'], byteorder='big')
            if 'notify_private' in result['tags_array'] or highlight:
                self.highlight(result['prefix'][5:], result['message'], highlight)

    def highlight(self, prefix, message, highlight=False):
        if self.notification:
            self.notification.close()
        if highlight:
            summary = 'New highlight'
        else:
            summary = 'New message from {}'.format(prefix)
        self.notification = notify2.Notification(summary, message, 'user-available-symbolic')
        self.notification.show()

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.loop.stop()


def create_ssl_context(cert_path):
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.load_verify_locations(cafile=cert_path)
    return ctx


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start the weechat relay listener.')
    parser.add_argument('host', help='Relay host')
    parser.add_argument('--password', help='Relay password')
    parser.add_argument('--password-cmd', help='Command to get relay password')
    parser.add_argument('-p', '--port', help='Relay port (9001)', type=int, default=9001)
    parser.add_argument('-s', '--ssl', help='Use ssl (true)', action='store_false', default=True)
    parser.add_argument('-c', '--ca-file', help="Path to the CA file to verify certificates")
    args = parser.parse_args()

    ssl_ctx = create_ssl_context(path.abspath(path.expanduser(args.ca_file))) if args.ssl else False

    if args.password_cmd:
        password = subprocess.check_output(args.password_cmd, shell=True).decode('utf-8')
    elif args.password:
        password = args.password
    else:
        print('missing either --password or --password-cmd')
        exit(-1)

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: WeechatRelayListener(password, loop),
                                  args.host, args.port, ssl=ssl_ctx)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
