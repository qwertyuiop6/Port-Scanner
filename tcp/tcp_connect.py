import sys
import time
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
sys.path.append('../')
from utils.log import log


class conn(object):
    def __init__(self, timeout=0.3, workers=500):
        self.log = log('TCP Connect scan--> ', 'Port-Scan')
        self.timeout = timeout
        self.workers = workers
        self.count = 0

    def run(self, ip='127.0.0.1', port=[1, 1080]):
        self.log.show('[Start TCP Connect Scan]--> [ip]:%s , [type]:%s' %
                      (ip, type(ip)))

        if type(ip) is str:
            self.start_scan(ip, port)
        else:
            for i in ip:
                self.start_scan(i, port)

    def start_scan(self, ip, port):
        t1 = time.time()
        if type(port) is list:
            with ThreadPoolExecutor(max_workers=self.workers) as e:
                e.map(self.scan_one, [ip for i in range(port[0], port[1] + 1)],
                      range(port[0], port[1] + 1),
                      timeout=self.timeout)
        else:
            self.scan_one(ip, port)
        t2 = time.time()
        print('主机: [%s] 发现 [%s] 个开放端口 ,耗时: %s 秒' % (ip, self.count, t2 - t1))

    def scan_one(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        addr = (ip, port)
        if s.connect_ex(addr) == 0:
            self.log.show('Host ip:[ %s ],Port:[ %s ] is open! ' % addr)
            self.count += 1
        s.close()


if __name__ == "__main__":
    app = conn()
    app.run()