import tensorflow as tf
import argparse as arp
import os.path as osp
import netifaces

from  time import sleep
from utils import Session

if __name__ == '__main__':

    tcp_gen_dir = 'generators/tcp'
    http_gen_dir = 'generators/http'

    parser = arp.ArgumentParser(description='Client')
    parser.add_argument('-i', '--iface', help='Interface', default='eth0')
    parser.add_argument('-r', '--remote', help='Remote', default='192.168.1.140')
    parser.add_argument('-p', '--port', help='Port', default=80, type=int)
    parser.add_argument('-t', '--traffic', help='Traffic', default='80_0')
    args = parser.parse_args()

    tcp_gen_path = osp.join(tcp_gen_dir, args.traffic)
    http_gen_path = osp.join(http_gen_dir, args.traffic)

    host = netifaces.ifaddresses(args.iface)[2][0]['addr']

    client = Session(host, args.remote, args.port, tcp_gen_path, http_gen_path)
    client.connect()
    client.send('123')
    client.close()

