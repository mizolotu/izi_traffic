import argparse as arp
import os.path as osp
import json

from time import sleep
from threading import Thread
from scapy_utils import scapy_sessions
from app_utils import app_sessions

if __name__ == '__main__':

    with open(osp.join('generators', 'tcp', 'metainfo.json'), 'r') as f:
        tcp_meta = json.load(f)
    with open(osp.join('generators', 'http', 'metainfo.json'), 'r') as f:
        http_meta = json.load(f)

    tcp_gen_dir = 'generators/tcp'
    http_gen_dir = 'generators/http'

    parser = arp.ArgumentParser(description='Client')
    parser.add_argument('-m', '--mode', help='Mode', default='app')
    parser.add_argument('-i', '--iface', help='Interface', default='eth0')
    parser.add_argument('-s', '--sport', help='Source port', default=0, type=int)
    parser.add_argument('-r', '--remote', help='Remote', default='172.17.0.2')
    parser.add_argument('-d', '--dport', help='Destination port', default=80, type=int)
    parser.add_argument('-t', '--traffic', help='Traffic', default='web_1')
    parser.add_argument('-f', '--flows', help='Number of flows', default=0, type=int)
    parser.add_argument('-n', '--nthreads', help='Number of flows', default=1, type=int)
    args = parser.parse_args()

    app = args.traffic.split('_')[0]
    label = int(args.traffic.split('_')[1])
    tcp_gen_path = osp.join(tcp_gen_dir, '{0}.tflite'.format(args.traffic))
    http_gen_path = osp.join(http_gen_dir, '{0}.tflite'.format(args.traffic))

    if args.mode == 'scapy':
        target = scapy_sessions
        targs = (args.iface, args.remote, args.dport, label, tcp_gen_path, http_gen_path, tcp_meta['xmin'], tcp_meta['xmax'], http_meta['xmin'], http_meta['xmax'], args.flows)
    elif args.mode == 'app':
        target = app_sessions
        targs = (app, args.remote, label)

    for i in range(args.nthreads):
        th = Thread(target=target, args=targs, daemon=True)
        th.start()

    while True:
        sleep(1)


