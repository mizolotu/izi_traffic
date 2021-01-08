import argparse as arp
import os.path as osp
import json

from utils import Session
from time import sleep
from threading import Thread

def session_after_session(sleep_interval=1):
    session = Session(args.iface, args.remote, args.dport, label, tcp_gen_path, http_gen_path, tcp_meta['xmin'], tcp_meta['xmax'], http_meta['xmin'], http_meta['xmax'])
    session.connect()
    session.send()
    flow_count = 1
    while True:
        if flow_count >= args.flows:
            break
        if session.connected:
            sleep(sleep_interval)
        else:
            session = Session(args.iface, args.remote, args.dport, label, tcp_gen_path, http_gen_path, tcp_meta['xmin'], tcp_meta['xmax'], http_meta['xmin'], http_meta['xmax'])
            session.connect()
            session.send()
            flow_count += 1


if __name__ == '__main__':

    with open(osp.join('generators', 'tcp', 'metainfo.json'), 'r') as f:
        tcp_meta = json.load(f)
    with open(osp.join('generators', 'http', 'metainfo.json'), 'r') as f:
        http_meta = json.load(f)

    tcp_gen_dir = 'generators/tcp'
    http_gen_dir = 'generators/http'

    parser = arp.ArgumentParser(description='Client')
    parser.add_argument('-i', '--iface', help='Interface', default='eth0')
    parser.add_argument('-s', '--sport', help='Source port', default=0, type=int)
    parser.add_argument('-r', '--remote', help='Remote', default='172.17.0.1')
    parser.add_argument('-d', '--dport', help='Destination port', default=80, type=int)
    parser.add_argument('-t', '--traffic', help='Traffic', default='80_0')
    parser.add_argument('-f', '--flows', help='Number of flows', default=1, type=int)
    parser.add_argument('-n', '--nthreads', help='Number of flows', default=1, type=int)
    args = parser.parse_args()

    label = int(args.traffic.split('_')[1])
    tcp_gen_path = osp.join(tcp_gen_dir, '{0}.tflite'.format(args.traffic))
    http_gen_path = osp.join(http_gen_dir, '{0}.tflite'.format(args.traffic))

    for i in range(args.nthreads):
        th = Thread(target=session_after_session, daemon=True)
        th.start()

    while True:
        sleep(1)


