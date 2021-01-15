import tflite_runtime.interpreter as tflite
import argparse as arp
import os.path as osp
import numpy as np
import json

from sklearn.manifold import TSNE
from plot_utils import generate_marker_scatter
import plotly.io as pio
import plotly.graph_objs as go

if __name__ == '__main__':

    postfix = 'generation'
    parser = arp.ArgumentParser(description='Test generator')
    parser.add_argument('-i', '--input', help='Samples', default='samples')
    parser.add_argument('-f', '--figures', help='Figures', default='figures/tsne')
    parser.add_argument('-t', '--traffic', help='Traffic', default='tcp')
    parser.add_argument('-d', '--direction', help='Direction', default='client')
    parser.add_argument('-n', '--normal', help='Normal label', default='80_0')
    parser.add_argument('-a', '--attack', help='Attack label', default='80_7')
    args = parser.parse_args()

    with open(osp.join('generators', 'tcp', 'metainfo.json'), 'r') as f:
        meta = json.load(f)
    xmin = np.array(meta['xmin'])
    xmax = np.array(meta['xmax'])

    model_file = osp.join('generators', 'tcp', '{0}.tflite'.format(args.normal))
    interpreter = tflite.Interpreter(model_path=model_file)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    input_shape = input_details[0]['shape']
    input_data = np.array(np.random.random_sample(input_shape), dtype=np.float32)
    batch_size = input_shape[0]
    input1 = np.array(np.random.randn(batch_size, 3), dtype=np.float32)
    if args.direction == 'client':
        fake_input = np.array(np.vstack([
            np.hstack([np.ones((batch_size, 1)), np.zeros((batch_size, 1)), np.zeros((batch_size, 3)), np.ones((batch_size, 2)), np.zeros((batch_size, 3))])
        ]), dtype=np.float32)
    else:
        fake_input = np.array(np.vstack([
            np.hstack([np.zeros((batch_size, 1)), np.ones((batch_size, 1)), np.zeros((batch_size, 3)), np.ones((batch_size, 2)), np.zeros((batch_size, 3))])
        ]), dtype=np.float32)
    interpreter.set_tensor(input_details[0]['index'], input1)
    interpreter.set_tensor(input_details[1]['index'], fake_input)
    interpreter.invoke()
    fake0 = interpreter.get_tensor(output_details[0]['index'])

    model_file = osp.join('generators', 'tcp', '{0}.tflite'.format(args.attack))
    interpreter = tflite.Interpreter(model_path=model_file)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    interpreter.set_tensor(input_details[0]['index'], input1)
    interpreter.set_tensor(input_details[1]['index'], fake_input)
    interpreter.invoke()
    fake1 = interpreter.get_tensor(output_details[0]['index'])

    fpath0 = osp.join(args.input, '{0}_{1}_{2}.csv'.format(args.traffic, args.normal, args.direction))
    real0 = np.genfromtxt(fpath0)

    fpath1 = osp.join(args.input, '{0}_{1}_{2}.csv'.format(args.traffic, args.attack, args.direction))
    real1 = np.genfromtxt(fpath1)

    X = np.vstack([
        real0,
        real1,
        fake0,
        fake1
    ])

    X_embedded = X # TSNE(n_components=2).fit_transform(X)
    names = [
        'Normal (real)',
        'Attack (real)',
        'Normal (fake)',
        'Attack (fake)'
    ]
    data = [
        [X_embedded[0:batch_size, 0], X_embedded[0:batch_size, 1]],
        [X_embedded[batch_size:batch_size*2, 0], X_embedded[batch_size:batch_size*2, 1]],
        [X_embedded[batch_size*2:batch_size*3, 0], X_embedded[batch_size*2:batch_size*3, 1]],
        [X_embedded[batch_size*3:batch_size*4, 0], X_embedded[batch_size*3:batch_size*4, 1]]
    ]

    colors = ['rgb(64,120,211)', 'rgb(237,2,11)', 'rgb(64,120,211)', 'rgb(237,2,11)']
    fills = ['rgb(255,255,255)', 'rgb(255,255,255)', 'rgb(0,0,0)', 'rgb(0,0,0)']
    traces, layout = generate_marker_scatter(names, data, colors, fills, xlabel='t-SNE feature 1', ylabel='t-SNE feature 2', show_legend=True)

    # save results

    ftypes = ['png', 'pdf']
    fig_fname = '{0}/{1}_{2}_{3}'.format(args.figures, args.traffic, args.attack, args.direction)
    fig = go.Figure(data=traces, layout=layout)
    for ftype in ftypes:
        pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))



