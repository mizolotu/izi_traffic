import argparse as arp
import json
import os.path as osp

from utils import *
from tf_utils import *
from time import time
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score

import tflite_runtime.interpreter as tflite

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Detect intrusions')
    parser.add_argument('-i', '--input', help='Directory with datasets')
    parser.add_argument('-o', '--output', help='Directory with trained models')
    parser.add_argument('-m', '--models', help='Directory with models', default='classifiers')
    parser.add_argument('-l', '--label', help='Attack label', default='7')
    parser.add_argument('-t', '--task', default='tcp', help='Task')
    parser.add_argument('-x', '--exclude', help='Features to exclude', default='48,49')

    args = parser.parse_args()

    # global params

    seed = 0
    batch_size = 1

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

    fpaths_star = [osp.join(fpath, '701_80*') for fpath in fpaths]
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
        if p < 0.98976469039917:
            p = 0
        else:
            p = 1
        if p == l:
            n_correct += 1
        else:
            n_incorrect += 1
        #print('Accuracy = {0}'.format(n_correct / (n_correct + n_incorrect)))
        count += 1
        if count >= 100:
            break
    sk_auc = roc_auc_score(testy, probs)
    print(sk_auc)

