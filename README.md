# Python 端口扫描器

> a simple python port scanner

## 支持端口扫描类型:

### 全连接扫描

- TCP CONNECT

### 半连接扫描

- TCP SYN

### 秘密扫描

- TCP ACK
- TCP FIN
- TCP NULL
- TCP Xmas Tree

## 主机存活探测(ping 扫描):

- ICMP echo

## How Use?

> pip install -r requirements.txt

```bash
# 默认使用Connect,可选具体主机ip或网段
python ps.py {ip | network}

# 指定端口
python ps.py {ip | network} -p 80

# 指定扫描方式(root)
python ps.py {ip | network} -ps {syn,ack,fin,null,xmas}

# Ping扫描探测主机存活(root)
python ps.py {ip | network} -pi

```

## How works?

- stream socket
- scapy
- icmp echo request
- raw socket
- futures threadpool
- logging
