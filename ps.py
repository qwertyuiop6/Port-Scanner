#!/usr/bin/python3
import argparse
from utils.util import get_port, get_ip
from tcp.tcp_connect import conn
from tcp.scapy_syn import syn
from tcp.scapy_ack import ack
from icmp.icmp_echo import icmp_live_scan
from tcp.scapy_fin_null_xmas import fin_null_xmas


class Port_Scanner(object):
    def __init__(self, params):
        self.params = params

    def check_ip_port(self, params):
        # for k, v in params.items():
        #     print(k, v)

        ip = get_ip(params['target'])
        if ip is False:
            print(
                '[[error]]: input target host address or network is not valid!'
            )
            return False

        port = get_port(params['port'])
        if port is False:
            print('[[error]]: input target port is not valid!')
            return False

        return (ip, port)

    def run(self):
        params = self.params
        res = self.check_ip_port(params)
        if res:
            ip, port = res
            if params['ping']:
                self.ping = icmp_live_scan()
                self.ping.run(ip)
            else:
                if params['ps'] in ['fin', 'null', 'xmas']:
                    self.pscanner = fin_null_xmas(params['ps'],
                                                  params['timeout'],
                                                  params['workers'])
                    self.pscanner.run(ip, port)
                else:
                    self.pscanner = eval(params['ps'])(params['timeout'],
                                                       params['workers'])
                    self.pscanner.run(ip, port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='A simple port scanner tool code by python')

    parser.add_argument('target', help='scan host\'s ip_address or network')
    parser.add_argument('-pi',
                        '--ping',
                        action='store_true',
                        help='ping host,ICMP echo scan')
    parser.add_argument(
        '-ps',
        choices=['conn', 'syn', 'ack', 'fin', 'null', 'xmas'],
        help=
        'TCP port scan, three ways:[connect, syn, ack, fin, null ,xmas],defult is connect',
        default='conn')
    parser.add_argument('-p', '--port', default='1-65535', help='port range')
    parser.add_argument('-t', '--timeout', default=0.2, help='timeout')
    parser.add_argument('-w', '--workers', default=500, help='worker threads')

    args = parser.parse_args()
    params = vars(args)

    app = Port_Scanner(params)
    app.run()