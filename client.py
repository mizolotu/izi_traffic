import tensorflow as tf
import argparse as arp
import os.path as osp
import socket

from  time import sleep
from utils import Client

if __name__ == '__main__':

    tcp_gen_dir = 'generators/tcp'
    http_gen_dir = 'generators/http'

    parser = arp.ArgumentParser(description='Client')
    parser.add_argument('-r', '--remote', help='Remote', default='130.234.169.76')
    parser.add_argument('-p', '--port', help='Port', default=80, type=int)
    parser.add_argument('-t', '--traffic', help='Traffic', default='80_0')
    args = parser.parse_args()

    hostname = socket.gethostname()
    host = socket.gethostbyname(hostname)
    tcp_gen_path = osp.join(tcp_gen_dir, args.traffic)
    http_gen_path = osp.join(http_gen_dir, args.traffic)

    client = Client(host, args.remote, args.port, tcp_gen_path, http_gen_path)
    client.connect()

