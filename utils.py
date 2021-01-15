import subprocess
import tflite_runtime.interpreter as tflite
import netifaces, socket
import numpy as np

from scapy.all import sniff, IP, TCP, RandShort, send, sr1, Raw, L3RawSocket, MTU
from threading import Thread
from time import sleep, time
from _thread import start_new_thread

def generate(interpreter, direction, flags):
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    input1_shape = input_details[0]['shape']
    batchsize = input1_shape[0]
    input1 = np.array(np.random.randn(batchsize, input1_shape[1]), dtype=np.float32)
    direction = np.ones((batchsize, 1)) * np.array(direction)
    flags = np.ones((batchsize, 1)) * np.array(flags)
    input2 = np.array(np.hstack([direction, flags]), dtype=np.float32)
    interpreter.set_tensor(input_details[0]['index'], input1)
    interpreter.set_tensor(input_details[1]['index'], input2)
    interpreter.invoke()
    x = interpreter.get_tensor(output_details[0]['index'])
    return x

def restore_tcp(x, xmin, xmax):
    x = np.clip(x, xmin, xmax)
    p = x * (xmax - xmin)[None, :] + xmin[None, :]
    iats = p[:, 0] - xmin[0]
    psizes = [int(np.ceil(item)) for item in p[:, 1]]
    wsizes = [int(np.ceil(item)) for item in p[:, 2]]
    return iats, psizes, wsizes

def restore_http(x, xmin, xmax, psizes):
    x = np.clip(x, xmin, xmax)
    p = x * (xmax - xmin)[None, :] + xmin[None, :]
    payloads = []
    for item, psize in zip(p, psizes):
        probs = item / np.sum(item)
        payloads.append(''.join([chr(a) for a in np.random.choice(256, psize, p=probs)]))
    return payloads

class Connection():

    def __init__(self, ip, port, seq, nmax):
        self.ip = ip
        self.port = port
        self.seq = seq
        self.ack = seq + 1
        self.npkts = 1
        self.nmax = nmax
        self.lasttime = time()
        self.status = 'syn'

class Server():

    def __init__(self, iface, port, label, tcp_gen_path, http_gen_path, nmin, nmax, tcp_x_min, tcp_x_max, http_x_min, http_x_max, timeout=30, debug=False):
        self.debug = debug
        self.timeout = timeout
        self.iface = iface
        self.ip = netifaces.ifaddresses(iface)[2][0]['addr']
        self.port = port
        self.label = 1 if label > 0 else 0
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        self.clients = []
        self.nmin, self.nmax = nmin, nmax
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        tcp_x_min = np.array(tcp_x_min)
        tcp_x_max = np.array(tcp_x_max)
        http_x_min = np.array(http_x_min)
        http_x_max = np.array(http_x_max)
        self.iats_psh, self.psizes_psh, self.wsizes_psh = restore_tcp(generate(self.tcp_interpreter, [0, 1], [0, 0, 0, 1, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.iats_ack, self.psizes_ack, self.wsizes_ack = restore_tcp(generate(self.tcp_interpreter, [0, 1], [0, 0, 0, 0, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.payloads = restore_http(generate(self.http_interpreter, [0, 1], [0, 0, 0, 1, 1, 0, 0, 0]), http_x_min, http_x_max, self.psizes_psh)
        clean_thr = Thread(target=self.clean_connections, daemon=True)
        clean_thr.start()

    def clean_connections(self, sleep_interval=1):
        while True:
            for i, conn in enumerate(self.clients):
                if time() - conn.lasttime > self.timeout:
                    self.clients.remove(conn)
            if self.debug:
                subprocess.call('clear')
                for i, conn in enumerate(self.clients):
                    print('Client {0}: {1}/{2}'.format(i, conn.npkts, conn.nmax))
            sleep(sleep_interval)

    def listen(self, iface=None):
        if iface is None:
            iface = self.iface
        sniff(prn=self.process, iface=iface, filter='dst {0} and dst port {1}'.format(self.ip, self.port), store=True)

    def process(self, pkt):
        if pkt.haslayer(TCP):
            src = pkt[IP].src
            sport = pkt[TCP].sport
            flags = pkt[TCP].flags
            tos = pkt[IP].tos
            if flags == 'S':
                nmax = np.random.randint(self.nmin, self.nmax)
                nmax = np.minimum(nmax, len(self.iats_ack) + len(self.iats_psh))
                potential_clients = [client for client in self.clients if client.ip == src and client.port == sport]
                if len(potential_clients) == 0:
                    client = Connection(pkt[IP].src, pkt[TCP].sport, pkt.seq, nmax)
                    idx = np.random.randint(0, len(self.iats_ack))
                    pkt_delay = self.iats_ack[idx]
                    window = self.wsizes_ack[idx]
                    ip = IP(src=self.ip, dst=client.ip, tos=tos|self.label)
                    tcp = TCP(sport=self.port, dport=client.port, flags="SA", seq=client.seq, ack=client.ack, options=[('MSS', 1460)], window=window)
                    sleep(pkt_delay)
                    send(ip / tcp, verbose=0)
                    client.status = 'syn-ack'
                    client.npkts += 1
                    self.clients.append(client)
            else:
                potential_clients = [client for client in self.clients if client.ip == src and client.port == sport]
                if len(potential_clients) == 1:

                    client = potential_clients[0]
                    ip = IP(src=self.ip, dst=client.ip, tos=tos | self.label)
                    client.lasttime = time()

                    if flags == 'A':
                        client.seq = pkt[TCP].ack
                        if client.status == 'syn-ack':

                            client.status = 'established'
                            client.npkts += 1

                        elif client.status == 'established':
                            if client.npkts >= client.nmax:

                                idx = np.random.randint(0, len(self.iats_psh))
                                pkt_delay = self.iats_ack[idx]
                                window = self.wsizes_ack[idx]
                                tcp = TCP(sport=self.port, dport=client.port, flags="FA", seq=client.seq, ack=client.ack, window=window)
                                sleep(pkt_delay)
                                send(ip/tcp, verbose=0)

                                client.seq += 1
                                client.status = 'close-wait'
                                client.npkts += 2

                        elif client.status == 'close-wait':

                            client.status = 'closed'
                            client.npkts += 1

                    elif flags == 'PA':

                        client.ack = pkt[TCP].seq + len(pkt[Raw])
                        idx = np.random.randint(0, len(self.iats_psh))
                        pkt_delay = self.iats_ack[idx]
                        window = self.wsizes_ack[idx]
                        ack = ip / TCP(sport=self.port, dport=client.port, flags='A', seq=client.seq, ack=client.ack, window=window)
                        sleep(pkt_delay)
                        send(ack, verbose=0)

                        idx = np.random.randint(0, len(self.iats_psh))
                        pkt_delay = self.iats_psh[idx]
                        window = self.wsizes_psh[idx]
                        raw = self.payloads[idx]
                        tcp = TCP(sport=self.port, dport=client.port, flags="PA", seq=client.seq, ack=client.ack, window=window)
                        sleep(pkt_delay)
                        send(ip/tcp/raw, verbose=0)
                        client.npkts  += 3

                    elif flags == 'FA':
                        if client.status == 'close-wait':

                            client.status = 'closed'
                            client.ack = pkt[TCP].seq + 1
                            idx = np.random.randint(0, len(self.iats_psh))
                            pkt_delay = self.iats_ack[idx]
                            window = self.wsizes_ack[idx]
                            ack = ip / TCP(sport=self.port, dport=client.port, flags='A', seq=client.seq, ack=client.ack, window=window)
                            sleep(pkt_delay)
                            send(ack, verbose=0)
                            client.npkts += 2
                            self.clients.remove(client)

                        elif client.status == 'established':

                            idx = np.random.randint(0, len(self.iats_psh))
                            pkt_delay = self.iats_ack[idx]
                            window = self.wsizes_ack[idx]
                            tcp = TCP(sport=self.port, dport=client.port, flags="FA", seq=client.seq, ack=client.ack, window=window)
                            sleep(pkt_delay)
                            send(ip / tcp, verbose=0)
                            client.status = 'close-wait'
                            client.npkts += 2

class Session():

    def __init__(self, iface, remote, dport, label, tcp_gen_path, http_gen_path, tcp_x_min, tcp_x_max, http_x_min, http_x_max, timeout=30):
        self.host = netifaces.ifaddresses(iface)[2][0]['addr']
        self.sport = self._get_free_port()
        self.remote = remote
        self.dport = dport
        self.label = 1 if label > 0 else 0
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        tcp_x_min = np.array(tcp_x_min)
        tcp_x_max = np.array(tcp_x_max)
        http_x_min = np.array(http_x_min)
        http_x_max = np.array(http_x_max)
        self.iats_psh, self.psizes_psh, self.wsizes_psh = restore_tcp(generate(self.tcp_interpreter, [0, 1], [0, 0, 0, 1, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.iats_ack, self.psizes_ack, self.wsizes_ack = restore_tcp(generate(self.tcp_interpreter, [0, 1], [0, 0, 0, 0, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.payloads = restore_http(generate(self.http_interpreter, [0, 1], [0, 0, 0, 1, 1, 0, 0, 0]), http_x_min, http_x_max, self.psizes_psh)
        self.timeout = timeout

    def _get_free_port(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(('', 0))
        addr, port = tcp.getsockname()
        tcp.close()
        return port

    def connect(self):
        try:
            self.seq = np.random.randint(0, (2 ** 32) - 1)
            syn = IP(src=self.host, dst=self.remote, tos=self.label) / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
            syn_ack = sr1(syn, timeout=self.timeout, verbose=0)
            self.seq += 1
            self.ack = syn_ack[TCP].seq + 1
            idx = np.random.randint(0, len(self.iats_ack))
            pkt_delay = self.iats_ack[idx]
            window = self.wsizes_ack[idx]
            ack = IP(src=self.host, dst=self.remote, tos=syn_ack[IP].tos|self.label) / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack, window=window)
            sleep(pkt_delay)
            send(ack, verbose=0)
            self.connected = True
            self._start_ack_thread()
        except:
            pass

    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        idx = np.random.randint(0, len(self.iats_ack))
        pkt_delay = self.iats_ack[idx]
        window = self.wsizes_ack[idx]
        ack = IP(src=self.host, dst=self.remote, tos=p[IP].tos|self.label) / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack, window=window)
        sleep(pkt_delay)
        send(ack, verbose=0)

    def _ack_rclose(self, p):
        self.connected = False
        self.ack += 1
        idx = np.random.randint(0, len(self.iats_ack))
        pkt_delay = self.iats_ack[idx]
        window = self.wsizes_ack[idx]
        fin_ack = IP(src=self.host, dst=self.remote, tos=p[IP].tos|self.label) / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack, window=window)
        sleep(pkt_delay)
        sr1(fin_ack, timeout=self.timeout, verbose=0)
        self.seq += 1

    def _sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == self.sport:
                self._ack(p)
                self.send()
            elif p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].flags & 0x01 == 0x01:  # FIN
                self._ack_rclose(p)
        s.close()
        self._ackThread = None

    def _start_ack_thread(self):
        self._ackThread = Thread(name='ack_thread', target=self._sniff)
        self._ackThread.start()

    def close(self):

        self.connected = False
        idx = np.random.randint(0, len(self.iats_ack))
        pkt_delay = self.iats_ack[idx]
        window = self.wsizes_ack[idx]
        fin = IP(src=self.host, dst=self.remote, tos=self.label) / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack, window=window)
        sleep(pkt_delay)
        fin_ack = sr1(fin, timeout=self.timeout, verbose=0)

        self.seq += 1
        self.ack = fin_ack[TCP].seq + 1
        idx = np.random.randint(0, len(self.iats_ack))
        pkt_delay = self.iats_ack[idx]
        window = self.wsizes_ack[idx]
        ack = IP(src=self.host, dst=self.remote, tos=fin_ack[IP].tos|self.label) / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack, window=window)
        sleep(pkt_delay)
        send(ack, verbose=0)

    def build(self, payload, window):
        psh = IP(src=self.host, dst=self.remote, tos=self.label) / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack, window=window) / payload
        self.seq += len(psh[Raw])
        return psh

    def send(self):
        idx = np.random.randint(0, len(self.iats_psh))
        pkt_delay = self.iats_psh[idx]
        window = self.wsizes_psh[idx]
        raw = self.payloads[idx]
        psh = self.build(raw, window)
        sleep(pkt_delay)
        sr1(psh, timeout=self.timeout, verbose=0)

class SocketClient():

    def __init__(self, sport, remote, dport, tcp_gen_path, http_gen_path, tcp_x_min, tcp_x_max, http_x_min, http_x_max, npkts_min, npkts_max):
        self.sport = sport
        self.dport = dport
        self.remote = remote
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        self.last_time = time()
        self.npkts_now = 0
        self.debug = False
        tcp_x_min = np.array(tcp_x_min)
        tcp_x_max = np.array(tcp_x_max)
        http_x_min = np.array(http_x_min)
        http_x_max = np.array(http_x_max)
        self.iats_psh, self.psizes_psh, self.wsizes_psh = restore_tcp(generate(self.tcp_interpreter, [1, 0], [0, 0, 0, 1, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.iats_ack, self.psizes_ack, self.wsizes_ack = restore_tcp(generate(self.tcp_interpreter, [1, 0], [0, 0, 0, 0, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.payloads = restore_http(generate(self.http_interpreter, [1, 0], [0, 0, 0, 1, 1, 0, 0, 0]), http_x_min, http_x_max, self.psizes_psh)
        self.npkts = np.minimum(np.random.randint(npkts_min, npkts_max), len(self.payloads))

    def connect(self):
        self.t_start = time()
        self.sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sckt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sckt.bind(('', self.sport))
        ready = False
        while not ready:
            try:
                self.sckt.connect((self.remote, self.dport))
                ready = True
            except Exception as e:
                print(e)
        self.last_time = time()
        self.npkts_now = 3

    def send_and_rcv(self):
        while self.npkts_now < self.npkts:
            self._send_req()
        self._close()

    def _send_req(self):
        idx = np.random.randint(0, len(self.iats_psh))
        pkt_delay = self.iats_psh[idx]
        recv_buff = self.wsizes_psh[idx]
        payload = self.payloads[idx]
        self.npkts_now += 2
        t_now = time()
        #if pkt_delay > t_now - self.last_time:
        #sleep(np.maximum(0, pkt_delay - t_now + self.last_time))
        sleep(pkt_delay)
        self.sckt.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buff)
        try:
            t_start_send = time()
            self.sckt.sendall(payload.encode('utf-8'))
            t_sent = time() - t_start_send
            if self.debug:
                print('PACKET SENT:')
                print(payload)
            t_rpl_start = time()
            ack = self._recv_rpl()
            t_rpl_proc = time() - t_rpl_start
            if self.debug:
                print('Time to send: {0}, time to process: {1}'.format(t_sent, t_rpl_proc))
        except Exception as e:
            print(e)
            ack = False
        return ack

    def _recv_rpl(self):
        try:
            idx = np.random.randint(0, len(self.iats_ack))
            pkt_delay = self.iats_ack[idx]
            sleep(pkt_delay)
            reply = self.sckt.recv(4096).decode('utf-8')
            if self.debug:
                print('PACKET RECEIVED:')
                print(reply)
            ack = True
        except Exception as e:
            print(e)
            ack = False
        return ack

    def _close(self):
        self.sckt.close()

class SocketServer():

    def __init__(self, port, tcp_gen_path, http_gen_path, tcp_x_min, tcp_x_max, http_x_min, http_x_max):
        host = '0.0.0.0'
        port = 80
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        tcp_x_min = np.array(tcp_x_min)
        tcp_x_max = np.array(tcp_x_max)
        http_x_min = np.array(http_x_min)
        http_x_max = np.array(http_x_max)
        self.iats_psh, self.psizes_psh, self.wsizes_psh = restore_tcp(generate(self.tcp_interpreter, [0, 1], [0, 0, 0, 1, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.iats_ack, self.psizes_ack, self.wsizes_ack = restore_tcp(generate(self.tcp_interpreter, [0, 1], [0, 0, 0, 0, 1, 0, 0, 0]), tcp_x_min, tcp_x_max)
        self.payloads = restore_http(generate(self.http_interpreter, [0, 1], [0, 0, 0, 1, 1, 0, 0, 0]), http_x_min, http_x_max, self.psizes_psh)

    def threaded_client(self, connection):
        last_time = time()
        idx = np.random.randint(0, len(self.iats_psh))
        pkt_delay = self.iats_psh[idx]
        recv_buff = self.wsizes_psh[idx]
        payload = self.payloads[idx]
        t_now = time()
        #if pkt_delay > t_now - last_time:
        #    sleep(np.maximum(0, pkt_delay - t_now + last_time))
        sleep(pkt_delay)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buff)
        connection.send(payload.encode('utf-8'))
        last_time = time()
        while True:
            idx = np.random.randint(0, len(self.iats_ack))
            pkt_delay = self.iats_ack[idx]
            sleep(pkt_delay)
            data = connection.recv(2048)
            idx = np.random.randint(0, len(self.iats_psh))
            pkt_delay = self.iats_psh[idx]
            recv_buff = self.wsizes_psh[idx]
            payload = self.payloads[idx]
            t_now = time()
            #if pkt_delay > t_now - last_time:
            #    sleep(np.maximum(0, pkt_delay - t_now + last_time))
            sleep(pkt_delay)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buff)
            if not data:
                break
            connection.sendall(payload.encode('utf-8'))
            last_time = time()
        connection.close()

    def serve(self):
        ThreadCount = 0
        while True:
            try:
                client_connection, client_address = self.server_socket.accept()
                start_new_thread(self.threaded_client, (client_connection,))
                ThreadCount += 1
            except Exception as e:
                print(e)
