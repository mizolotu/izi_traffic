import numpy as np
import tensorflow as tf
from baselines.common.runners import AbstractEnvRunner
from threading import Thread
from queue import Queue
from time import time

class Runner(AbstractEnvRunner):
    """
    We use this object to make a mini batch of experiences
    __init__:
    - Initialize the runner

    run():
    - Make a mini batch
    """
    def __init__(self, *, env, model, nsteps, gamma, lam):
        super().__init__(env=env, model=model, nsteps=nsteps)
        # Lambda used in GAE (General Advantage Estimation)
        self.lam = lam
        # Discount rate
        self.gamma = gamma
        self.cum_rew = np.zeros(env.num_envs)
        self.cum_time = np.zeros(env.num_envs)
        self.cum_steps = np.zeros(env.num_envs)

    def run_env(self, env_idx, obs, done, q):
        scores = []
        cum_rew_list = []
        cum_time_list = []
        cum_step_list = []
        obss, actions, values, states, neglogpacs, rewards, dones = [], [], [], [], [], [], []
        for _ in range(self.nsteps):
            obs_ = tf.constant(obs.reshape(1, obs.shape[0], obs.shape[1]), dtype=tf.float32)
            action, value, state, neglogpac = self.model.step(obs_)
            actions.append(action[0])
            values.append(value[0])
            states.append(state)
            neglogpacs.append(neglogpac[0])
            obss.append(obs)
            dones.append(done)
            self.dones[env_idx] = done
            obs, reward, done, info = self.env.step_env(env_idx, action[0])
            rewards.append(reward)

            if 'r' in info.keys() and 'l' in info.keys() and 't' in info.keys():
                scores.append(info['r'])
                self.cum_rew[env_idx] += info['r']
                self.cum_time[env_idx] += info['t']
                self.cum_steps[env_idx] = info['l']

            if done:
                cum_rew_list.append(self.cum_rew[env_idx])
                cum_time_list.append(self.cum_time[env_idx])
                cum_step_list.append(self.cum_steps[env_idx])
                self.cum_rew[env_idx] = 0
                self.cum_time[env_idx] = 0
                self.cum_steps[env_idx] = 0

        cum_rew_avg = np.mean(cum_rew_list) if len(cum_rew_list) > 0 else self.cum_rew[env_idx]
        cum_time_avg = np.mean(cum_time_list) if len(cum_time_list) > 0 else self.cum_time[env_idx]
        cum_steps_avg = np.mean(cum_step_list) if len(cum_step_list) > 0 else self.cum_steps[env_idx]
        epinfos = {'r': np.mean(scores), 'L': cum_steps_avg, 'R': cum_rew_avg, 'T': cum_time_avg}
        q.put((obss, actions, values, states, neglogpacs, rewards, dones, epinfos))

    def run(self):

        # Here, we init the lists that will contain the mb of experiences

        mb_obs, mb_rewards, mb_actions, mb_values, mb_dones, mb_neglogpacs = [],[],[],[],[],[]
        mb_states = self.states
        epinfos = []

        thrs = []
        q = Queue()
        for env_i in range(self.env.num_envs):
            thrs.append(Thread(target=self.run_env, args=(env_i, self.obs[env_i], self.dones[env_i], q), daemon=True))
            thrs[env_i].start()
        for env_i in range(self.env.num_envs):
            thrs[env_i].join()

        obs_list, action_list, value_list, neglogpac_list, reward_list, done_list, epinfo_list = [], [], [], [], [], [], []
        for i in range(self.env.num_envs):
            obs, actions, values, states, neglogpacs, rewards, dones, epinfo = q.get()
            obs_list.append(obs)
            action_list.append(actions)
            value_list.append(values)
            neglogpac_list.append(neglogpacs)
            reward_list.append(rewards),
            done_list.append(dones)
            epinfos.append(epinfo)

        for step in range(self.nsteps):
            mb_obs.append([item[step] for item in obs_list])
            mb_actions.append([item[step] for item in action_list])
            mb_values.append([item[step] for item in value_list])
            mb_neglogpacs.append([item[step] for item in neglogpac_list])
            mb_dones.append([item[step] for item in done_list])
            mb_rewards.append([item[step] for item in reward_list])

        #batch of steps to batch of rollouts

        mb_obs = np.asarray(mb_obs, dtype=self.obs.dtype)
        mb_rewards = np.asarray(mb_rewards, dtype=np.float32)
        mb_actions = np.asarray(mb_actions)
        mb_values = np.asarray(mb_values, dtype=np.float32)
        mb_neglogpacs = np.asarray(mb_neglogpacs, dtype=np.float32)
        mb_dones = np.asarray(mb_dones, dtype=np.bool)

        last_values = self.model.value(tf.constant(self.obs))._numpy()
        self.dones = np.array(self.dones)

        # discount/bootstrap off value fn
        mb_returns = np.zeros_like(mb_rewards)
        mb_advs = np.zeros_like(mb_rewards)
        lastgaelam = 0
        for t in reversed(range(self.nsteps)):
            if t == self.nsteps - 1:
                nextnonterminal = 1.0 - self.dones
                nextvalues = last_values
            else:
                nextnonterminal = 1.0 - mb_dones[t+1]
                nextvalues = mb_values[t+1]
            delta = mb_rewards[t] + self.gamma * nextvalues * nextnonterminal - mb_values[t]
            mb_advs[t] = lastgaelam = delta + self.gamma * self.lam * nextnonterminal * lastgaelam
        mb_returns = mb_advs + mb_values
        return (*map(sf01, (mb_obs, mb_returns, mb_dones, mb_actions, mb_values, mb_neglogpacs)),
            mb_states, epinfos)


def sf01(arr):
    """
    swap and then flatten axes 0 and 1
    """
    s = arr.shape
    return arr.swapaxes(0, 1).reshape(s[0] * s[1], *s[2:])
