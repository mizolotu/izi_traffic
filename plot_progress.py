import numpy as np
import pandas
import plotly as pl
import plotly.io as pio
import plotly.graph_objs as go

def baseline(x, nsteps=100):
    n = x.shape[0]
    b = []
    for i in range(nsteps):
        b.append(x[np.random.choice(n), :])
    return np.vstack(b)

def moving_average(x, step=1, window=10):
    seq = []
    n = x.shape[0]
    for i in np.arange(0, n, step):
        idx = np.arange(np.maximum(0, i - window), np.minimum(n - 1, i + window + 1))
        seq.append(np.mean(x[idx, :], axis=0))
    return np.vstack(seq)

def plot_progress(R, dx=16000):

    # layout

    layout = go.Layout(
        template='plotly_white',
        margin={'t': 0, 'l': 0, 'b': 0, 'r': 10},
        xaxis=dict(
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False,
            title='Steps (total packets sent)'
        ),
        yaxis=dict(
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False,
            title='Score (attack accuracy)'
        ),
    )

    # traces

    dir = 'figs'
    names = ['PPO']
    data = [R[0]]
    colors = ['rgb(237,2,11)', 'rgb(64,120,211)']
    x = (dx * np.arange(data[0].shape[0])).tolist()
    traces = []
    for i in range(len(data)):
        y = data[i][:, 0].tolist()
        traces.append(go.Scatter(
            x=x,
            y=y,
            line=dict(color=colors[i]),
            mode='lines',
            showlegend=False,
            name=names[i]
        ))
    fig = go.Figure(data=traces, layout=layout)
    pio.write_image(fig, '{0}/score.png'.format(dir))
    pio.write_image(fig, '{0}/score.pdf'.format(dir))

if __name__ == '__main__':

    # load progressbr

    policies = ['ppo']
    fname = 'logs/web/{0}/progress.csv'
    keys = ['stats/score']
    R = []
    for policy in policies:
        p = pandas.read_csv(fname.format(policy), delimiter=',', dtype=float)
        k = [key for key in p.keys()]
        v = p.values[1:, :]
        r = np.zeros((v.shape[0], len(keys)))
        for i,key in enumerate(keys):
            idx = k.index(key)
            r[:, i] = v[:, idx]
    R.append(moving_average(r))
    n = R[0].shape[0]

    # plot progress

    plot_progress(R)