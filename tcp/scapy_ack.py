import sys
import time
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
sys.path.append('../')
from utils.log import log


class ack(object):
    def __init__(self, timeout=0.3, workers=500):
        self.log = log('TCP ACK Scan--> ', 'Port-Scan')
        self.timeout = timeout
        self.workers = workers
        self.source_ip = '192.168.1.200'
        self.count = 0
        self.unfilter = []

    def run(self, ip='127.0.0.1', port=[1, 1500]):
        self.log.show('[Start TCP ACK Scan]--> [ip]:%s , [type]:%s' %
                      (ip, type(ip)))
        if type(ip) is str:
            self.start_scan(ip, port)
        else:
            for i in ip:
                self.start_scan(i, port)

    def start_scan(self, ip, port):
        t1 = time.time()
        if type(port) is list:
            port = [1, 3000]
            with ThreadPoolExecutor(max_workers=self.workers) as e:
                e.map(self.scan_one, [ip for i in range(port[0], port[1] + 1)],
                      range(port[0], port[1] + 1),
                      timeout=self.timeout)
        else:
            self.scan_one(ip, port)
        t2 = time.time()
        print(
            '主机: [%s]扫描%d个端口\n发现 [%s] 个被过滤,[%s] 个未过滤可能开放的端口 : %s,耗时: %.3f 秒' %
            (ip, port[1], port[1] - len(self.unfilter), len(
                self.unfilter), self.unfilter, t2 - t1))

    def scan_one(self, dst_ip, dst_port):
        src_port = RandShort()

        scan_resp = sr1(
            IP(dst=dst_ip) / TCP(dport=dst_port, flags="A"),  #发送ACK报文
            timeout=2,
            verbose=False)

        if scan_resp:
            self.count += 1
            if (scan_resp.haslayer(TCP)):
                if (scan_resp.getlayer(TCP).flags == 0x04
                    ):  #收到RST回应则该端口未被过滤，但开放和关闭具体无法得知
                    self.log.show("%s:[%s] is unfilter, maybe open" %
                                  (dst_ip, dst_port))
                    # self.count += 1
                    self.unfilter.append(dst_port)
            elif scan_resp.haslayer(ICMP):
                if int(scan_resp.getlayer(ICMP).type) == 3 and int(
                        scan_resp.getlayer(ICMP).code) in [
                            1, 2, 3, 9, 10, 13
                        ]:  #若响应ICMP type 3, code 这些类型说明目标不可达被过滤
                    print("filter")
        else:  #未回应则说明端口被过滤
            self.log.show("%s:[%s] is filter" % (dst_ip, dst_port))

    if __name__ == "__main__":
        app = ack()
        app.run()