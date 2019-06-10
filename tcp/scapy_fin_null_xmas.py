import sys
import time
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
sys.path.append('../')
from utils.log import log


class fin_null_xmas(object):
    def __init__(self, flag='fin', timeout=0.3, workers=500):
        self.log = log('TCP %s Scan--> ' % flag, 'Port-Scan')
        self.timeout = timeout
        self.workers = workers
        self.source_ip = '192.168.1.200'
        self.count = 0
        self.flag = flag

    def run(self, ip='127.0.0.1', port=[1, 1500]):
        self.log.show('[Start TCP %s Scan]--> [ip]:%s , [type]:%s' %
                      (self.flag, ip, type(ip)))

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
        print('主机: [%s] 发现 [%s] 个被过滤可能开放的端口 ,耗时: %.3f 秒' %
              (ip, self.count, t2 - t1))

    def scan_one(self, dst_ip, dst_port):
        method_flags = {'fin': 'F', 'null': '', 'xmas': 'UPF'}
        scan_resp = sr1(IP(dst=dst_ip) /
                        TCP(dport=dst_port, flags=method_flags[self.flag]),
                        timeout=2,
                        verbose=False)

        if scan_resp:
            if (scan_resp.haslayer(TCP)):
                if (scan_resp.getlayer(TCP).flags == 0x04):
                    self.log.show(
                        "%s:[%s] is Closed" % (dst_ip, dst_port)
                    )  #响应RST认为该端口关闭,(对于windows,由于不遵守RFC793,无论如何都回复RST)
            elif scan_resp.haslayer(ICMP):
                if int(scan_resp.getlayer(ICMP).type) == 3 and int(
                        scan_resp.getlayer(ICMP).code) in [
                            1, 2, 3, 9, 10, 13
                        ]:  #若响应ICMP type 3, code 这些类型说明目标不可达被过滤
                    print("filter")
        else:
            self.log.show("%s:[%s] is open or filter" %
                          (dst_ip, dst_port))  #若无响应，则认为端口开放或被过滤
            self.count += 1

        #   FIN ,Null, Xmas 3种扫描均无响应，手动scapy发包也都无响应,wireshark抓包无果,使用nmap扫描也是全部无响应,
        #   可能探测报文被 包过滤 阻止到达端口

    if __name__ == "__main__":
        app = fin_null_xmas()
        app.run()
