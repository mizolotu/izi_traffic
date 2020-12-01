import sys
import numpy as np

from baselines.common.vec_env import SubprocVecEnv
from baselines.ppo2.ppo2 import learn as learn_ppo
from baselines.ddpg.ddpg import learn as learn_ddpg
from env import DeEnv
from time import sleep

def create_env(iface, port, remote, url, attack, state_height):
    return lambda : DeEnv(iface, port, remote, url, attack, state_height)

if __name__ == '__main__':

    # args

    iface = sys.argv[1]
    server_ip = sys.argv[2]
    learner = eval('learn_{0}'.format(sys.argv[3]))
    policy = sys.argv[4]
    nenvs = int(sys.argv[5])
    nupdates = int(sys.argv[6])

    # envs

    nsteps = 200
    ports = [12340 + i for i in range(nenvs)]
    env_fns = [create_env(iface, port, (server_ip, 80), '/DVWA-master/login.php', 'bruteforce', 64) for port in ports]
    env = SubprocVecEnv(env_fns)
    learner(env=env, network=policy, nsteps=nsteps, total_timesteps=nsteps*nenvs*nupdates)
