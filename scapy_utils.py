import subprocess
import tflite_runtime.interpreter as tflite
import netifaces, socket
import numpy as np

from scapy.all import sniff, IP, TCP, RandShort, send, sr1, Raw, L3RawSocket, MTU
from threading import Thread
from time import sleep, time

def scapy_sessions(iface, remote, dport, label, tgp, hgp, tmin, tmax, hmin, hmax, flows, sleep_interval=1):
    session = Session(iface, remote, dport, label, tgp, hgp, tmin, tmax, hmin, hmax)
    session.connect()
    session.send()
    flow_count = 1
    while True:
        if flows > 0 and flow_count >= flows:
            break
        if session.connected:
            sleep(sleep_interval)
        else:
            session = Session(iface, remote, dport, label, tgp, hgp, tmin, tmax, hmin, hmax)
            session.connect()
            session.send()
            flow_count += 1
            if flows > 0:
                print(flow_count)

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

class ScapyServer():

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

    def serve(self, iface=None):
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