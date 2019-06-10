import sys
import socket
import ipaddress
import os
import struct
import array
import time
from concurrent.futures import ThreadPoolExecutor
sys.path.append('../')
from utils.log import log


class icmp_live_scan(object):
    def __init__(self, timeout=2, workers=500):
        self.log = log('ICMP echo ping host--> ', 'IP-Scan')
        self.timeout = timeout
        self.workers = workers
        self.data = struct.pack('d', time.time())  # 用于ICMP报文的负荷字节（8bytes）
        self.pid = os.getpid()  # 构造ICMP报文的ID字段，填入进程pid
        self.times = {}
        self.icmp_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW,
            socket.getprotobyname("icmp"))  # ICMP Socket

    @property
    def icmp_packet(self):
        '''构造 ICMP 报文'''
        header = struct.pack('bbHHh', 8, 0, 0, self.pid,
                             0)  # TYPE、CODE、CHKSUM、ID、SEQ,  校验和先置0
        packet = header + self.data  # 初始包
        ckSum = self.checkSum(packet)  # 加入数据后计算校验和
        header = struct.pack('bbHHh', 8, 0, ckSum, self.pid, 0)  # 头部加入校验和
        return header + self.data  # 打包头+数据, Echo request——回显请求（Ping请求）构建完成

    def checkSum(self, packet):
        '''ICMP 报文效验和计算'''
        if len(packet) & 1:
            packet = packet + '\0'  #转为偶数字节包
        words = array.array('h', packet)  #转为2字节一组的数组

        sum = 0  # 一个4字节整数
        for word in words:
            sum += (word & 0xffff)  #2字节一组循环加　求二进制和

        sum = (sum >> 16) + (sum & 0xffff)  #高16bit加低16bit
        sum += (sum >> 16)  # 如果还有高于16位，将继续与低16位相加

        return (~sum) & 0xffff  #返回取反的和

    def run(self, ipPool='127.0.0.1'):
        self.log.show('[[Start icmp echo ping]]--> [ip]:%s , [type]:%s' %
                      (ipPool, type(ipPool)))
        t1 = time.time()
        self.alive_list = []

        self.ping(ipPool)

        t2 = time.time()
        if len(self.alive_list):
            self.log.show(
                '>> IP扫描完成,耗时: %.3f 秒,\n>> 存活主机[%d]: %s' %
                (t2 - t1, len(self.alive_list), str(self.alive_list)))
        else:
            self.log.show('>> 耗时: %.3f 秒, 目标无响应' % (t2 - t1))

    def ping(self, ipPool):
        '''
        利用ICMP报文探测网络主机存活
        '''
        self.icmp_socket.settimeout(self.timeout)

        if type(ipPool) is str:
            self.send_ping(ipPool)
        else:
            with ThreadPoolExecutor(max_workers=self.workers) as e:
                e.map(self.send_ping, [str(ip) for ip in ipPool])

    def send_ping(self, ipPool):
        packet = self.icmp_packet
        Sock = self.icmp_socket
        t1 = time.time()
        self.times[ipPool] = t1  #记录开始时间

        try:
            Sock.sendto(packet, (ipPool, 0))
        except socket.timeout:
            self.log.err('sendto %s timeout' % ipPool)

        try:
            recv = self.icmp_socket.recvfrom(1024)  # 接收回显应答报文
            res, addr = recv
            # print(res, len(res))
            icmp_header = res[20:28]  #从IP后８byte提取ICMP头
            rtype, code, cksum, pid, seq = struct.unpack(
                'bbHHh', icmp_header)  # 解包 TYPE、CODE、CHKSUM、ID、SEQ
            # print(rtype, code, cksum, pid, seq)

            if pid == self.pid:  # 通过响应包头部的ID段判断包是否是对本ip scan进程的回复
                ip = addr[0]
                spend_time = time.time() - self.times[ip]  #计算往返时延rtt
                self.log.show('>> %s icmp reply, time= %.2f ms, it\'s alive!' %
                              (ip, spend_time * 1000))

                self.alive_list.append(ip)  #加入到响应的主机列表
        except Exception:
            pass
        # finally:
        #     break


if __name__ == "__main__":
    app = icmp_live_scan()
    app.run('127.0.0.1')