import sys, pickle
import os.path as osp

from data_proc import find_data_files
from pcap_proc import read_pcap

def attack_fields(pcap_file):
    headers, payloads = read_pcap(pcap_file)
    lens = {'get': [], 'post': [], 'x-a': []}
    for payload in payloads:
        for key in lens.keys():
            if key in payload.lower():
                if len(payload) not in lens[key]:
                    lens[key].append(len(payload))
    return lens

if __name__ == '__main__':

    # files

    dir = sys.argv[1]
    pcap_files = find_data_files(dir, postfix='.pcap')

    # init attack probiles

    attack_profiles = {
        'botnet': [],
        'bruteforce': [],
        'goldeneye': [],
        'hulk': [],
        'slowloris': []
    }

    # main loop

    for pcap_file in pcap_files:
        print(pcap_file)
        attack_profile_key = osp.basename(pcap_file).split('_')[0]
        attack_profiles[attack_profile_key] = attack_fields(pcap_file)

    # save lens

    with open(osp.join(dir, 'profiles.pkl'), 'wb') as f:
        pickle.dump(attack_profiles, f)

