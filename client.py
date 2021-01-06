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
    parser.add_argument('-s', '--sport', help='Source port', default=1337, type=int)
    parser.add_argument('-r', '--remote', help='Remote', default='172.17.0.1')
    parser.add_argument('-d', '--dport', help='Destination port', default=80, type=int)
    parser.add_argument('-t', '--traffic', help='Traffic', default='80_0')
    args = parser.parse_args()

    tcp_gen_path = osp.join(tcp_gen_dir, '{0}.tflite'.format(args.traffic))
    http_gen_path = osp.join(http_gen_dir, '{0}.tflite'.format(args.traffic))

    host = netifaces.ifaddresses(args.iface)[2][0]['addr']

    client = Session(host, args.remote, args.port, tcp_gen_path, http_gen_path)
    client.connect()
    client.send('123')
    client.close()

