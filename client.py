import argparse as arp
import os.path as osp
import json

from utils import Client

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
    args = parser.parse_args()

    tcp_gen_path = osp.join(tcp_gen_dir, '{0}.tflite'.format(args.traffic))
    http_gen_path = osp.join(http_gen_dir, '{0}.tflite'.format(args.traffic))

    client = Client(
        args.sport, args.remote, args.dport,
        tcp_gen_path, http_gen_path,
        tcp_meta['xmin'], tcp_meta['xmax'],
        http_meta['xmin'], http_meta['xmax'],
        tcp_meta['nmin'][args.traffic], tcp_meta['nmax'][args.traffic]
    )
    client.connect()
    client.send_and_rcv()
