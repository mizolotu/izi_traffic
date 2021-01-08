import argparse as arp
import os.path as osp
import json

from utils import Server

if __name__ == '__main__':

    with open(osp.join('generators', 'tcp', 'metainfo.json'), 'r') as f:
        tcp_meta = json.load(f)
    with open(osp.join('generators', 'http', 'metainfo.json'), 'r') as f:
        http_meta = json.load(f)

    tcp_gen_dir = 'generators/tcp'
    http_gen_dir = 'generators/http'

    parser = arp.ArgumentParser(description='Server')
    parser.add_argument('-i', '--iface', help='Interface', default='eth0')
    parser.add_argument('-p', '--port', help='Port', default=80, type=int)
    parser.add_argument('-t', '--traffic', help='Traffic', default='80_0')
    parser.add_argument('-d', '--debug', help='Debug mode', default='False', type=bool)
    args = parser.parse_args()

    label = int(args.traffic.split('_')[1])
    tcp_gen_path = osp.join(tcp_gen_dir, '{0}.tflite'.format(args.traffic))
    http_gen_path = osp.join(http_gen_dir, '{0}.tflite'.format(args.traffic))

    #server = Server(args.port, tcp_gen_path, http_gen_path, tcp_meta['xmin'], tcp_meta['xmax'], http_meta['xmin'], http_meta['xmax'])
    server = Server(args.iface, args.port, label, tcp_gen_path, http_gen_path, tcp_meta['nmin'][args.traffic], tcp_meta['nmax'][args.traffic], tcp_meta['xmin'], tcp_meta['xmax'], http_meta['xmin'], http_meta['xmax'], debug=args.debug)
    #server.serve()
    server.listen()


