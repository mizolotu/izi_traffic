import argparse as arp
import json, os
import os.path as osp
import tflite_runtime.interpreter as tflite
import plotly.io as pio
import plotly.graph_objs as go
import numpy as np

#from utils import *
from tf_utils import *
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from plot_utils import generate_roc_scatter

if __name__ == '__main__':

    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

    parser = arp.ArgumentParser(description='Detect intrusions')
    parser.add_argument('-i', '--input', help='Directory with datasets')
    parser.add_argument('-o', '--output', help='Directory with trained models')
    parser.add_argument('-m', '--models', help='Directory with models', default='classifiers')
    parser.add_argument('-l', '--label', help='Attack label', default='7')
    parser.add_argument('-t', '--task', default='tcp', help='Task')
    parser.add_argument('-x', '--exclude', help='Features to exclude', default='')
    parser.add_argument('-f', '--figures', help='Directory with figures', default='figures/rocs')
    args = parser.parse_args()

    # global params

    seed = 0
    batch_size = 1
    max_count = 10000
    fpr_levels=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

    # set seed for results reproduction

    tf.random.set_seed(seed)
    np.random.seed(seed)

    # inputs

    input_task = osp.join(args.input, '{0}_classification'.format(args.task))
    fpaths = [
        osp.join(input_task, '0'),
        osp.join(input_task, args.label),
    ]

    with open(osp.join(args.models, args.task, 'metainfo.json')) as f:
        meta = json.load(f)

    # fpath

    fpaths_star = [osp.join(fpath, '701_*') for fpath in fpaths]
    #fpaths_star = [osp.join(fpath, '*_test') for fpath in fpaths]

    # meta

    nfeatures = meta['nfeatures']
    xmin = np.array(meta['xmin'])
    xmax = np.array(meta['xmax'])

    # features

    # mappers

    cl_mapper = lambda x,y: classification_mapper(x, y, xmin=xmin, xmax=xmax)
    ex_idx = np.ones(nfeatures - 1)
    if len(args.exclude) > 0:
        for item in args.exclude.split(','):
            ex_idx[int(item)] = 0
    ex_mapper = lambda x, y: exclude_feature_mapper(x, y, ex_idx)

    batches = {}
    batches_ = [
        load_batches(fpaths_star[0], batch_size, nfeatures, nfeatures).map(cl_mapper).map(ex_mapper),
        load_batches(fpaths_star[1], batch_size, nfeatures, nfeatures).map(cl_mapper).map(ex_mapper)
    ]
    batches = tf.data.experimental.sample_from_datasets([batches_[0], batches_[1]], [0.5, 0.5]).unbatch().shuffle(batch_size).batch(batch_size)

    model_label = args.label
    interpreter = tflite.Interpreter(model_path=osp.join(args.models, args.task, '{0}.tflite'.format(model_label)))
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    input1_shape = input_details[0]['shape']
    n_correct = 0
    n_incorrect = 0
    count = 0
    probs = []
    testy = []
    for x,y in batches:
        interpreter.set_tensor(input_details[0]['index'], x)
        interpreter.invoke()
        p = interpreter.get_tensor(output_details[0]['index'])[0][0]
        probs.append(p)
        l = np.array(y)[0]
        testy.append(l)
        print(p, l)
        count += 1
        if count >= max_count:
            break
    sk_auc = roc_auc_score(testy, probs)
    print('AUC = {0}'.format(sk_auc))
    ns_fpr , ns_tpr, ns_thr = roc_curve(testy, probs)
    thrs = []
    for fpr_level in fpr_levels:
        idx = np.where(ns_fpr <= fpr_level)[0][-1]
        thrs.append(str(ns_thr[idx]))
        print(ns_tpr[idx])
    with open(osp.join(args.models, args.task, '{0}.thr'.format(model_label)), 'w') as f:
        f.write(','.join(thrs))

    # plot

    if args.task == 'tcp':
        colors = ['rgb(64,120,211)']
    else:
        colors = ['rgb(237,2,11)']
    data = [[ns_fpr, ns_tpr]]
    names = ['Attack {0} detection via {1} features'.format(args.label, args.task.upper())]
    traces, layout = generate_roc_scatter(names, data, colors)

    # save results

    ftypes = ['png', 'pdf']
    fig_fname = '{0}/{1}_{2}_fake'.format(args.figures, args.task, args.label)
    fig = go.Figure(data=traces, layout=layout)
    for ftype in ftypes:
        pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))