import queue
import random
import threading
import socket


def _get_port_queue(port_pool, tcp, udp):
    res = queue.Queue()
    [res.put(i) for i in
     [('tcp', x) for x in port_pool if tcp] + [('udp', x) for x in
                                               port_pool if udp]]
    return res


class Scanner:
    def __init__(self, host, port_pool, tcp=True, udp=True, timeout=0.5,
                 workers=10):
        self.host = host
        self.port_queue = _get_port_queue(port_pool, tcp, udp)
        self.results = queue.Queue()
        self.rnd_time = random.randint(2 ** 16, 2 ** 64 - 1).to_bytes(8, 'big')
        self.udp_data = b'\x13' + b'\0' * 39 + self.rnd_time
        self.threads = [threading.Thread(target=self._check_port, daemon=True)
                        for _ in range(workers)]
        socket.setdefaulttimeout(timeout)

    def start(self):
        for t in self.threads:
            t.start()
        while self.port_queue.qsize() > 0:
            try:
                print(self.results.get(block=False))
            except queue.Empty:
                pass
        for t in self.threads:
            t.join()
        while not self.results.qsize() == 0:
            print(self.results.get())

    def _check_port(self):
        try:
            while True:
                conn_type, port = self.port_queue.get(block=False)
                if conn_type == 'tcp':
                    self._check_tcp(port)
                elif conn_type == 'udp':
                    self._check_udp(port)
        except queue.Empty:
            return

    def _check_tcp(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ind = sock.connect_ex((self.host, port))
        if not ind:
            try:
                sock1 = socket.socket()
                sock1.connect((self.host, port))
                sock1.send(b'a' * 250 + b'\r\n\r\n')
                data = sock1.recv(1024)
                self.results.put(f'TCP {port} {self.parse_proto(data)}')
                sock1.close()
            except Exception:
                self.results.put(f'TCP {port}')

        sock.close()

    def _check_udp(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ind = sock.connect_ex((self.host, port))
        if not ind:
            try:
                sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock1.sendto(self.udp_data, (self.host, port))
                data, host = sock1.recvfrom(1024)
                self.results.put(f'UDP {port} {self.parse_proto(data)}')
                sock1.close()
            except ConnectionRefusedError:
                pass
            except socket.timeout:
                self.results.put(f'UDP {port}')
        sock.close()

    def parse_proto(self, data):
        if len(data) > 4 and data[:4] == b'HTTP':
            return 'HTTP'
        if b'SMTP' in data:
            return 'SMTP'
        if b'POP3' in data:
            return 'POP3'
        if b'IMAP' in data:
            return 'IMAP'
        if (len(data) > 11 and data[:2] == self.udp_data[:2] and
                data[3] & 1 == 1):
            return 'DNS'
        if len(data) > 39:
            if (7 & data[0] == 4 and
                    (data[0] >> 3) & 7 == 2 and self.rnd_time == data[24:32]):
                return 'NTP'
        return ""
