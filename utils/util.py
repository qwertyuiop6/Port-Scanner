import ipaddress


def get_ip(str):
    """
    """
    try:
        if '/' in str:
            network = ipaddress.ip_network(str)
            return network.hosts()
        else:
            ipaddress.ip_address(str)
            return str
    except ValueError:
        return False


def get_port(str):
    try:
        if '-' in str:
            l = str.split('-')
            port_list = []

            for port in l:
                if port == '':
                    return False
                port_list.append(int(port))

            if len(port_list) > 2:
                return False

            return sorted(port_list)
        else:
            return int(str)

    except ValueError:
        return False


if __name__ == "__main__":
    test_ip = [
        '1.1', '2.2.1', 'asd', '256.1.1.1', '127.0.0.1', '192.168.0.1/24',
        '192.168.0.0/24'
    ]
    for i in test_ip:
        print(get_ip(i))

    for i in get_ip('192.168.0.0/24'):
        print(i)

    test_port = ['-', '1-s', '1-', 's', '80', '1-1080', '2222-2']
    for i in test_port:
        print(get_port(i))
