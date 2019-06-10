import sys
import time
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
sys.path.append('../')
from utils.log import log


class syn(object):
    def __init__(self, timeout=0.3, workers=500):
        self.log = log('TCP SYN Scan--> ', 'Port-Scan')
        self.timeout = timeout
        self.workers = workers
        self.source_ip = '192.168.1.200'
        self.count = 0

    def run(self, ip='127.0.0.1', port=[1, 1080]):
        self.log.show('[Start TCP SYN Scan]--> [ip]:%s , [type]:%s' %
                      (ip, type(ip)))

        if type(ip) is str:
            self.start_scan(ip, port)
        else:
            for i in ip:
                self.start_scan(i, port)

    def start_scan(self, ip, port):
        t1 = time.time()
        if type(port) is list:
            port = [1, 4000]
            with ThreadPoolExecutor(max_workers=self.workers) as e:
                e.map(self.scan_one, [ip for i in range(port[0], port[1] + 1)],
                      range(port[0], port[1] + 1),
                      timeout=self.timeout)
        else:
            self.scan_one(ip, port)
        t2 = time.time()
        print('主机: [%s] 发现 [%s] 个开放端口 ,耗时: %.3fs 秒' %
              (ip, self.count, t2 - t1))

    def scan_one(self, dst_ip, dst_port):
        src_port = RandShort()

        scan_resp = sr1(IP(dst=dst_ip) /
                        TCP(sport=src_port, dport=dst_port, flags="S"),
                        timeout=0.5,
                        verbose=False)

        if scan_resp:
            if (scan_resp.haslayer(TCP)):
                if (scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(
                        IP(dst=dst_ip) /
                        TCP(sport=src_port, dport=dst_port, flags="R"),
                        timeout=0.2,
                        verbose=False)
                    self.log.show("%s:[%s] is open !" % (dst_ip, dst_port))
                    self.count += 1
                elif (scan_resp.getlayer(TCP).flags == 0x14):
                    # self.log.show("%s:[%s] is Closed" % (dst_ip, dst_port))
                    pass
            elif scan_resp.haslayer(ICMP):
                if int(scan_resp.getlayer(ICMP).type) == 3 and int(
                        scan_resp.getlayer(ICMP).code) in [
                            1, 2, 3, 9, 10, 13
                        ]:  #若响应ICMP type 3, code 这些类型说明目标不可达被过滤
                    print("filter")
        else:
            # self.log.show("%s:[%s] is Closed" % (dst_ip, dst_port))
            pass

    if __name__ == "__main__":
        app = syn()
        app.run()