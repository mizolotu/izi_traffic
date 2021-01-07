import numpy as np
import tflite_runtime.interpreter as tflite
import netifaces, socket

from scapy.all import sniff, IP, TCP, RandShort, send, sr1, Raw, L3RawSocket, MTU
from threading import Thread
from time import sleep, time

def restore_tcp(x, xmin, xmax):
    x = np.clip(x, xmin, xmax)
    p = x * (xmax - xmin) + xmin
    iat = p[0] - xmin[0]
    psize = int(p[1])
    wsize = int(p[2])
    return iat, psize, wsize

def restore_http(x, xmin, xmax, psize):
    x = np.clip(x, xmin, xmax)
    p = x * (xmax - xmin) + xmin
    payload = np.random.choice(256, psize, p=x)
    return

class Flow():

    def __init__(self, pkt, flags, blk_thr=1.0, idl_thr=5.0):

        self.blk_thr = blk_thr
        self.idl_thr = idl_thr

        # zero features

        self.fl_dur = 0

        self.tot_bw_pk = 0

        self.fw_pkt_l_std = 0

        self.bw_pkt_l_max = 0
        self.bw_pkt_l_min = 0
        self.bw_pkt_l_avg = 0
        self.bw_pkt_l_std = 0

        self.fl_byt_s = 0
        self.fl_pkt_s = 0
        self.fl_iat_avg = 0
        self.fl_iat_std = 0

        self.fl_iat_max = 0
        self.fl_iat_min = 0

        self.fw_iat_tot = 0
        self.fw_iat_avg = 0
        self.fw_iat_std = 0
        self.fw_iat_max = 0
        self.fw_iat_min = 0

        self.bw_iat_tot = 0
        self.bw_iat_avg = 0
        self.bw_iat_std = 0
        self.bw_iat_max = 0
        self.bw_iat_min = 0

        self.fw_psh_flag = 0
        self.bw_psh_flag = 0
        self.fw_urg_flag = 0
        self.bw_urg_flag = 0

        self.bw_hdr_len = 0

        self.fw_pkt_s = 0
        self.bw_pkt_s = 0

        self.pkt_len_std = 0

        self.down_up_ratio = 0

        self.fw_byt_blk_avg = 0
        self.fw_pkt_blk_avg = 0
        self.fw_blk_rate_avg = 0

        self.bw_byt_blk_avg = 0
        self.bw_pkt_blk_avg = 0
        self.bw_blk_rate_avg = 0

        self.fw_pkt_sub_avg = 0
        self.fw_byt_sub_avg = 0
        self.bw_pkt_sub_avg = 0
        self.bw_byt_sub_avg = 0

        self.bw_win_byt = 0

        self.atv_avg = 0
        self.atv_std = 0
        self.atv_max = 0
        self.atv_min = 0

        self.idl_avg = 0
        self.idl_std = 0
        self.idl_max = 0
        self.idl_min = 0

        self.flag_counts = [0 for _ in range(8)]

        # auxiliary metrics to calculate features

        self.last_bw_pkt_t = 0
        self.n_iat = 0
        self.n_fw_iat = 0
        self.n_bw_iat = 0

        self.fw_pkt_blk = 0
        self.fw_byt_blk = 0
        self.fw_dur_blk = 0

        self.bw_pkt_blk = 0
        self.bw_byt_blk = 0
        self.bw_dur_blk = 0
        self.bw_n_blk = 0

        self.fw_pkt_sub = 0
        self.fw_byt_sub = 0

        self.bw_pkt_sub = 0
        self.bw_byt_sub = 0
        self.bw_n_sub = 0

        self.t_idle_start = 0
        self.n_idle = 0

        # features

        if pkt[5] == 6: # check protocol
            self.is_tcp = 1
            self.is_udp = 0
        elif pkt[5] == 17: # check protocol
            self.is_tcp = 0
            self.is_udp = 1
        for i,flag in enumerate(flags):
            self.flag_counts[i] = flag if flag == 1 else self.flag_counts[i]
        self.tot_fw_pk = 1
        self.tot_l_fw_pkt = pkt[6]
        self.fw_pkt_l_max = pkt[6]
        self.fw_pkt_l_min = pkt[6]
        self.fw_pkt_l_avg = pkt[6]
        self.fw_hdr_len = pkt[7]
        self.pkt_len_min = pkt[6]
        self.pkt_len_max = pkt[6]
        self.pkt_len_avg = pkt[6]
        self.subfl_fw_pk = 1
        self.subfl_fw_byt = pkt[6]
        self.fw_win_byt = pkt[9]
        self.fw_act_pkt = 1 if pkt[8] > 0 else 0

        # auxiliary

        self.fl_byt = pkt[6]
        self.fl_pkt = 1
        self.last_pkt_t = pkt[0]
        self.last_fw_pkt_t = pkt[0]
        self.fw_n_blk = 1
        self.fw_n_sub = 1
        self.is_active = True
        self.n_active = 0
        self.t_active_start = pkt[0]

    def _new_mean_std(self, n, mu, std, value):
        new_n = n + 1
        new_mu = (n * mu + value) / new_n
        d1 = mu - new_mu
        d2 = value - new_mu
        new_std = np.sqrt((n * (d1 ** 2 + std ** 2) + (d2 ** 2)) / new_n)
        return new_n, new_mu, new_std

    def update(self, current_time):

        # recalculate features for a new time moment

        t_delta = current_time - self.last_pkt_t
        self.fl_dur += t_delta
        self.fl_pkt_s = self.fl_pkt / self.fl_dur
        self.fl_byt_s = self.fl_byt / self.fl_dur
        self.fw_pkt_s = self.tot_fw_pk / self.fl_dur
        self.bw_pkt_s = self.tot_bw_pk / self.fl_dur

        if self.is_active:
            if t_delta > self.idl_thr:
                self.is_active = False
                t_active = self.last_pkt_t - self.t_active_start
                if self.n_active == 0:
                    self.atv_min = t_active
                    self.atv_max = t_active
                    self.atv_avg = t_active
                    self.n_active = 1
                else:
                    self.n_active, self.atv_avg, self.atv_std = self._new_mean_std(self.n_active, self.atv_avg, self.atv_std, t_active)
                    self.atv_min = np.minimum(self.atv_min, t_active)
                    self.atv_max = np.maximum(self.atv_max, t_active)

    def append(self, pkt, flags, direction):

        # recalculate features when a new packet is added to the flow

        iat = pkt[0] - self.last_pkt_t
        if self.n_iat == 0:
            self.n_iat = 1
            self.fl_iat_avg = iat
            self.fl_iat_min = iat
            self.fl_iat_max = iat
        else:
            self.n_iat, self.fl_iat_avg, self.fl_iat_std = self._new_mean_std(self.n_iat, self.fl_iat_avg, self.fl_iat_std, iat)
            self.fl_iat_min = np.minimum(self.fl_iat_min, iat)
            self.fl_iat_max = np.maximum(self.fl_iat_max, iat)

        self.fl_dur += np.maximum(iat, 1e-10)
        self.fl_byt += pkt[6]
        self.fl_pkt, self.pkt_len_avg, self.pkt_len_std = self._new_mean_std(self.fl_pkt, self.pkt_len_avg, self.pkt_len_std, pkt[6])
        self.fl_pkt_s = self.fl_pkt / self.fl_dur
        self.fl_byt_s = self.fl_byt / self.fl_dur

        self.pkt_len_min = np.minimum(self.pkt_len_min, pkt[6])
        self.pkt_len_max = np.maximum(self.pkt_len_max, pkt[6])

        if self.is_active == True:
            if iat > self.idl_thr:
                t_active = self.last_pkt_t - self.t_active_start
                if self.n_active == 0:
                    self.atv_min = t_active
                    self.atv_max = t_active
                    self.atv_avg = t_active
                    self.n_active = 1
                else:
                    self.n_active, self.atv_avg, self.atv_std = self._new_mean_std(self.n_active, self.atv_avg, self.atv_std, t_active)
                    self.atv_min = np.minimum(self.atv_min, t_active)
                    self.atv_max = np.maximum(self.atv_max, t_active)
                self.t_active_start = pkt[0]
        elif self.is_active == False:
            self.is_active = True
            self.t_active_start = self.last_pkt_t
            t_idle = pkt[0] - self.t_idle_start
            if self.n_idle == 0:
                self.idl_min = t_idle
                self.idl_max = t_idle
                self.idl_avg = t_idle
                self.n_idle = 1
            else:
                self.n_idle, self.idl_avg, self.idl_std = self._new_mean_std(self.n_idle, self.idl_avg, self.idl_std, t_idle)
                self.idl_min = np.minimum(self.idl_min, t_idle)
                self.idl_max = np.maximum(self.idl_max, t_idle)

        if direction == 1:

            self.tot_fw_pk, self.fw_pkt_l_avg, self.fw_pkt_l_std = self._new_mean_std(self.tot_fw_pk, self.fw_pkt_l_avg, self.fw_pkt_l_std, pkt[6])
            self.tot_l_fw_pkt += pkt[6]
            self.fw_pkt_l_max = np.maximum(self.fw_pkt_l_max, pkt[6])
            self.fw_pkt_l_min = np.minimum(self.fw_pkt_l_min, pkt[6])
            fw_iat = np.maximum(pkt[0] - self.last_fw_pkt_t, 1e-10)
            if self.n_fw_iat == 0:
                self.n_fw_iat = 1
                self.fw_iat_avg = fw_iat
                self.fw_iat_min = fw_iat
                self.fw_iat_max = fw_iat
            else:
                self.n_fw_iat, self.fw_iat_avg, self.fw_iat_std = self._new_mean_std(self.n_fw_iat, self.fw_iat_avg, self.fw_iat_std, fw_iat)
                self.fw_iat_min = np.minimum(self.fw_iat_min, fw_iat)
                self.fw_iat_max = np.maximum(self.fw_iat_max, fw_iat)
            self.fw_psh_flag += flags[3]
            self.fw_urg_flag += flags[5]
            self.fw_hdr_len += pkt[7]
            self.fw_pkt_s = self.tot_fw_pk / self.fl_dur
            if pkt[8] > 0:
                self.fw_act_pkt += 1

            # bulk

            if fw_iat <= self.blk_thr:
                self.fw_pkt_blk += 1
                self.fw_byt_blk += pkt[6]
                self.fw_dur_blk += fw_iat
                self.fw_pkt_blk_avg = self.fw_pkt_blk / self.fw_n_blk
                self.fw_byt_blk_avg = self.fw_byt_blk / self.fw_pkt_blk
                self.fw_blk_rate_avg = self.fw_byt_blk / self.fw_dur_blk
            else:
                self.fw_n_blk += 1

            # subflow

            if fw_iat <= self.idl_thr:
                self.fw_pkt_sub += 1
                self.fw_byt_sub += pkt[6]
                self.fw_pkt_sub_avg = self.fw_pkt_sub / self.fw_n_sub
                self.fw_byt_sub_avg = self.fw_byt_sub / self.fw_pkt_sub
            else:
                self.fw_n_sub += 1

            self.last_fw_pkt_t = pkt[0]

        else:

            if self.tot_bw_pk == 0:
                self.bw_win_byt = pkt[9]
                self.tot_bw_pk = 1
                self.bw_pkt_l_max = pkt[6]
                self.bw_pkt_l_min = pkt[6]
                self.bw_pkt_l_avg = pkt[6]
                self.bw_hdr_len = pkt[7]
                self.subfl_bw_pk = 1
                self.subfl_bw_byt = pkt[6]
                self.bw_win_byt = pkt[9]
                self.bw_act_pkt = 1 if pkt[8] > 0 else 0
                self.last_bw_pkt_t = pkt[0]
                self.bw_n_blk = 1
                self.bw_n_sub = 1
            else:
                self.tot_bw_pk, self.bw_pkt_l_avg, self.bw_pkt_l_std = self._new_mean_std(self.tot_bw_pk, self.bw_pkt_l_avg, self.bw_pkt_l_std, pkt[6])
                self.bw_pkt_l_max = np.maximum(self.bw_pkt_l_max, pkt[6])
                self.bw_pkt_l_min = np.minimum(self.bw_pkt_l_min, pkt[6])
                bw_iat = np.maximum(pkt[0] - self.last_bw_pkt_t, 1e-10)
                if self.n_bw_iat == 0:
                    self.n_bw_iat = 1
                    self.bw_iat_avg = bw_iat
                    self.bw_iat_min = bw_iat
                    self.bw_iat_max = bw_iat
                else:
                    self.n_bw_iat, self.bw_iat_avg, self.bw_iat_std = self._new_mean_std(self.n_bw_iat, self.bw_iat_avg, self.bw_iat_std, bw_iat)
                    self.bw_iat_min = np.minimum(self.bw_iat_min, bw_iat)
                    self.bw_iat_max = np.maximum(self.bw_iat_max, bw_iat)
                if bw_iat <= self.blk_thr:
                    self.bw_pkt_blk += 1
                    self.bw_byt_blk += pkt[6]
                    self.bw_dur_blk += bw_iat
                    self.bw_pkt_blk_avg = self.bw_pkt_blk / self.bw_n_blk
                    self.bw_byt_blk_avg = self.bw_byt_blk / self.bw_pkt_blk
                    if self.bw_dur_blk == 0:
                        print(bw_iat)
                    self.bw_blk_rate_avg = self.bw_byt_blk / self.bw_dur_blk
                else:
                    self.bw_n_blk += 1
                if bw_iat <= self.idl_thr:
                    self.bw_pkt_sub += 1
                    self.bw_byt_sub += pkt[6]
                    self.bw_pkt_sub_avg = self.bw_pkt_sub / self.bw_n_sub
                    self.bw_byt_sub_avg = self.bw_byt_sub / self.bw_pkt_sub
                else:
                    self.bw_n_sub += 1
            self.bw_psh_flag += flags[3]
            self.bw_urg_flag += flags[5]
            self.bw_hdr_len += pkt[7]
            self.bw_pkt_s = self.tot_bw_pk / self.fl_dur

            self.last_bw_pkt_t = pkt[0]

        for i,flag in enumerate(flags):
            self.flag_counts[i] = flag if flag == 1 else self.flag_counts[i]

        self.down_up_ratio = self.tot_bw_pk / self.tot_fw_pk

        self.last_pkt_t = pkt[0]

    def get_features(self):
        return np.array([
            self.is_tcp,  # 1
            self.is_udp,  # 2
            self.fl_dur,  # 3
            self.tot_fw_pk,  # 4
            self.tot_bw_pk,  # 5
            self.tot_l_fw_pkt,  # 6
            self.fw_pkt_l_max,  # 7
            self.fw_pkt_l_min,  # 8
            self.fw_pkt_l_avg,  # 9
            self.fw_pkt_l_std,  # 10
            self.bw_pkt_l_max,  # 11
            self.bw_pkt_l_min,  # 12
            self.bw_pkt_l_avg,  # 13
            self.bw_pkt_l_std,  # 14
            self.fl_byt_s,  # 15
            self.fl_pkt_s,  # 16
            self.fl_iat_avg,  # 17
            self.fl_iat_std,  # 18
            self.fl_iat_max,  # 19
            self.fl_iat_min,  # 20
            self.fw_iat_tot,  # 21
            self.fw_iat_avg,  # 22
            self.fw_iat_std,  # 23
            self.fw_iat_max,  # 24
            self.fw_iat_min,  # 25
            self.bw_iat_tot,  # 26
            self.bw_iat_avg,  # 27
            self.bw_iat_std,  # 28
            self.bw_iat_max,  # 29
            self.bw_iat_min,  # 30
            self.fw_psh_flag,  # 31
            self.bw_psh_flag,  # 32
            self.fw_urg_flag,  # 33 -
            self.bw_urg_flag,  # 34 -
            self.fw_hdr_len,  # 35
            self.bw_hdr_len,  # 36
            self.fw_pkt_s,  # 37
            self.bw_pkt_s,  # 38
            self.pkt_len_min,  # 39
            self.pkt_len_max,  # 40
            self.pkt_len_avg,  # 41
            self.pkt_len_std,  # 42
            *self.flag_counts, # 43 - 50
            self.down_up_ratio,  # 51
            self.fw_byt_blk_avg,  # 52
            self.fw_pkt_blk_avg,  # 53
            self.fw_blk_rate_avg,  # 54
            self.bw_byt_blk_avg,  # 55
            self.bw_pkt_blk_avg,  # 56
            self.bw_blk_rate_avg,  # 57
            self.fw_pkt_sub_avg,  # 58
            self.fw_byt_sub_avg,  # 59
            self.bw_pkt_sub_avg,  # 60
            self.bw_byt_sub_avg,  # 61
            self.fw_win_byt,  # 62
            self.bw_win_byt,  # 63
            self.fw_act_pkt,  # 64
            self.atv_avg,  # 65
            self.atv_std,  # 66
            self.atv_max,  # 67
            self.atv_min,  # 68
            self.idl_avg,  # 69
            self.idl_std,  # 70
            self.idl_max,  # 71
            self.idl_min  # 72
        ])

class Client_():

    def __init__(self, ip, port, seq, nmax):
        self.ip = ip
        self.port = port
        self.seq = seq
        self.ack = seq + 1
        self.connected = False
        self.npkts = 1
        self.nmax = nmax

class Server_():

    def __init__(self, iface, port, tcp_gen_path, http_gen_path, nmin=10, nmax=15, timeout=3):
        self.iface = iface
        self.ip = netifaces.ifaddresses(iface)[2][0]['addr']
        self.port = port
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        self.clients = []
        self.timeout = timeout
        self.nmin, self.nmax = nmin, nmax

    def listen_(self, iface=None):
        if iface is None:
            iface = self.iface
        sniff(prn=self._complete_handshake, iface=iface, filter='dst {0} and dst port {1} and tcp[tcpflags] == tcp-syn'.format(self.ip, self.port))

    def listen(self, iface=None):
        if iface is None:
            iface = self.iface
        sniff(prn=self.process, iface=iface, filter='dst {0} and dst port {1}'.format(self.ip, self.port))

    def process(self, pkt):
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 'S':
                nmax = np.random.randint(self.nmin, self.nmax)
                client = Client(pkt[IP].src, pkt[TCP].sport, pkt.seq, nmax)
                print('New client')
                print(client.ip, client.port)
                ip = IP(src=self.ip, dst=client.ip)
                tcp = TCP(sport=self.port, dport=client.port, flags="SA", seq=client.seq, ack=client.ack, options=[('MSS', 1460)])
                ack = sr1(ip / tcp, timeout=self.timeout)
                client.connected = True
                client.npkts += 2
                self.clients.append(client)
                self._create_connection(client)

    def _complete_handshake(self, pkt):
        if pkt.haslayer(TCP):
            nmax = np.random.randint(self.nmin, self.nmax)
            client = Client(pkt[IP].src, pkt[TCP].sport, pkt.seq, nmax)
            print('New client')
            print(client.ip, client.port)
            ip = IP(src=self.ip, dst=client.ip)
            tcp = TCP(sport=self.port, dport=client.port, flags="SA", seq=client.seq, ack=client.ack, options=[('MSS', 1460)])
            ack = sr1(ip / tcp, timeout=self.timeout)
            client.connected = True
            client.npkts += 2
            self.clients.append(client)
            self._create_connection(client)

    def _ack(self, p, client):
        client.ack = p[TCP].seq + len(p[Raw])
        ack = IP(src=self.ip, dst=client.ip) / TCP(sport=self.port, dport=client.port, flags='A', seq=client.seq, ack=client.ack)
        send(ack)

    def _ack_rclose(self, client):
        client.connected = False
        client.ack += 1
        fin_ack = IP(src=self.ip, dst=client.ip) / TCP(sport=self.port, dport=client.port, flags='FA', seq=client.seq, ack=client.ack)
        ack = sr1(fin_ack, timeout=self.timeout)
        client.seq += 1

    def _sniff(self, client):
        s = L3RawSocket(filter='src {0} and src port {1} and dst {2} and dst port {3}'.format(client.ip, client.port, self.ip, self.port))
        while client.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == self.port and p[TCP].sport == client.port:
                self._ack(p, client)
                client.npkts += 2
                self.send('345', client)
                client.npkts += 2
                #if client.npkts >= client.nmax - 3:
                #     self.close(client)
            if p.haslayer(TCP) and p[TCP].dport == self.port and p[TCP].sport == client.port and p[TCP].flags & 0x01 == 0x01:  # FIN
                self._ack_rclose(client)
        s.close()

    def _create_connection(self, client):
        _connection_thread = Thread(target=self._sniff, args=(client, ), daemon=True)
        _connection_thread.start()

    def build(self, payload, client):
        psh = IP(src=self.ip, dst=client.ip) / TCP(sport=self.port, dport=client.port, flags='PA', seq=client.seq, ack=client.ack) / payload
        client.seq += len(psh[Raw])
        return psh

    def send(self, payload, client):
        psh = self.build(payload, client)
        sr1(psh, timeout=self.timeout)

    def close(self, client):
        client.connected = False
        fin = IP(src=self.ip, dst=client.ip) / TCP(sport=self.port, dport=client.port, flags='FA', seq=client.seq, ack=client.ack)
        fin_ack = sr1(fin, timeout=self.timeout)
        client.seq += 1
        client.ack = fin_ack[TCP].seq + 1
        ack = self.ip / TCP(sport=self.port, dport=client.port, flags='A', seq=client.seq, ack=client.ack)
        send(ack)

class Session():

    def __init__(self, host, sport, remote, dport, tcp_gen_path, http_gen_path, timeout=3):
        self.host = host
        self.sport = sport
        self.remote = remote
        self.dport = dport
        self.ip = IP(src=host, dst=remote)
        self.tcp_interpreter = tflite.Interpreter(model_path=tcp_gen_path)
        self.http_interpreter = tflite.Interpreter(model_path=http_gen_path)
        self.timeout = timeout

    def connect(self):
        self.seq = np.random.randint(0, (2 ** 32) - 1)
        syn = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
        syn_ack = sr1(syn, timeout=self.timeout)
        self.seq += 1
        self.ack = syn_ack[TCP].seq + 1
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        send(ack)
        self.connected = True
        self._start_ackThread()
        print('Connected')

    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack)

    def _ack_rclose(self):
        self.connected = False
        self.ack += 1
        fin_ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout=self.timeout)
        self.seq += 1

    def _sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == self.sport:
                print('received something')
                self._ack(p)
                self.send('345')
            if p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].flags & 0x01 == 0x01:  # FIN
                print('received fin')
                self._ack_rclose()
                print(self.connected)
        s.close()
        self._ackThread = None
        print('Acknowledgment thread stopped')

    def _start_ackThread(self):
        self._ackThread = Thread(name='AckThread', target=self._sniff)
        self._ackThread.start()

    def close(self):
        self.connected = False
        fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        fin_ack = sr1(fin, timeout=self.timeout)
        self.seq += 1
        self.ack = fin_ack[TCP].seq + 1
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack)
        print('Disconnected')

    def build(self, payload):
        psh = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payload
        self.seq += len(psh[Raw])
        return psh

    def send(self, payload):
        psh = self.build(payload)
        ack = sr1(psh, timeout=self.timeout)

class Client():

    def __init__(self, sport, remote, dport):
        self.sport = sport
        self.dport = dport
        self.remote = remote
        self.last_time = time()
        self.npkts = 0
        self.debug = True

    def connect(self):
        self.t_start = time()
        self.sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sckt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sckt.bind(('', self.port))
        ready = False
        while not ready:
            try:
                self.sckt.connect(self.remote)
                ready = True
            except Exception as e:
                pass
        self.last_time = time()

    def send_psh_ack(self):
        pkt_delay = 0
        payload_size = 100
        recv_buff = 10000
        pkt = '123'
        to_be_done = False
        self.npkts += 2
        t_now = time()
        if pkt_delay > t_now - self.last_time:
            sleep(np.maximum(0, pkt_delay - t_now + self.last_step_time))
        self.sckt.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buff)
        try:
            t_start_send = time()
            self.sckt.sendall(pkt.encode('utf-8'))
            t_sent = time() - t_start_send
            if self.debug:
                print('PACKET SENT:')
                print(pkt)
            t_rpl_start = time()
            ack = self._process_reply()
            t_rpl_proc = time() - t_rpl_start
            if self.debug:
                print('Time to send: {0}, time to process: {1}'.format(t_sent, t_rpl_proc))
        except Exception as e:
            pkts_req = None
            ack = False
            to_be_done = True

class Server():

    def __init__(self, port, tcp_gen_path, http_gen_path):
        host = '0.0.0.0'
        port = 80
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(1)
        print('Listening on port %s ...' % port)

    def serve(self):
        while True:
            client_connection, client_address = self.server_socket.accept()
            req = client_connection.recv(4096)
            print(req)
            response = 'HTTP/1.0 200 OK\n\nHello World'
            client_connection.sendall(response.encode())




