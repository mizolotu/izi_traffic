import os
import numpy as np
import os.path as osp

from sklearn.ensemble import BaggingClassifier
from sklearn.svm import SVC
from data_proc import load_dataset
from joblib import dump
from time import time

def ga_iteration(kernel, penalty, features, x_tr, y_tr, x_val, y_val):
    m, n = features.shape
    new_features = np.zeros((4 * m, n))
    new_features[:m, :] = features
    for i in range(m):
        p1 = features[np.random.randint(0, m), :]
        p2 = features[np.random.randint(0, m), :]
        co = np.random.randint(0, 2, (n,))
        new_features[m + i, np.where(co == 0)[0]] = p1[np.where(co == 0)[0]]
        new_features[m + i, np.where(co == 1)[0]] = p2[np.where(co == 1)[0]]
        mut = np.random.randint(0, 2, (n,))
        p = new_features[np.random.randint(0, m), :]
        new_features[2 * m + i, :] = p
        new_features[2 * m + i, np.where(mut == 1)[0]] = 1 - p[np.where(mut == 1)[0]]
        mut = np.random.randint(0, 2, (n,))
        p = new_features[m + np.random.randint(0, m), :]
        new_features[3 * m + i, :] = p
        new_features[3 * m + i, np.where(mut == 1)[0]] = 1 - p[np.where(mut == 1)[0]]
    f = np.zeros(4 * m)
    for i in range(4 * m):
        idx = np.where(new_features[i, :] == 1)[0]
        if len(idx) > 0:
            model = BaggingClassifier(SVC(kernel=kernel, C=penalty, cache_size=4096), n_estimators=10, max_samples=0.1, n_jobs=-1)
            t_start = time()
            model.fit(x_tr[:, idx], y_tr)
            #print('{0} seconds to fit'.format(time() - t_start))
            t_start = time()
            f[i] = model.score(x_val[:, idx], y_val)
            #print('{0} seconds to score'.format(time() - t_start))
    features_selected = new_features[np.argsort(f)[-m:], :]
    return features_selected, np.sort(f)[-m:]

if __name__ == '__main__':

    # load data

    X_tr, Y_tr, X_val, Y_val, X_te, Y_te = load_dataset('data/cicids2018', 'data', '.pkl', 'stats.pkl')
    nfeatures = X_tr.shape[1]
    nlabels = np.max(Y_tr) + 1
    print(X_tr.shape, Y_tr.shape, X_val.shape, Y_val.shape, X_te.shape, Y_te.shape)

    # lazy labeling: 0 or 1

    B_tr = Y_tr.copy()
    B_val = Y_val.copy()
    B_te = Y_te.copy()
    for b in [B_tr, B_val, B_te]:
        b[b > 0] = 1

    # test models

    model_save_dir = 'models/svm_{0}_{1}_{2}'
    model_checkpoint_file = 'ckpt'
    model_stats_file = 'metrics.txt'
    nsamples = X_tr.shape[0]
    n_ga_iterations = 100
    sample_size = int(nsamples * 0.001)
    population_size = 5
    kernels = ['rbf'] # ['linear', 'poly', 'rbf', 'sigmoid']
    penalties = [1.0] # [0.01, 0.1, 1.0, 10.0, 100.0]
    n_labels = [2, nlabels]
    features = np.vstack([
        np.ones((1, nfeatures)),
        np.random.randint(0, 2, (population_size - 1, nfeatures))
    ])
    for kernel in kernels:
        for penalty in penalties:
            for nn in n_labels:
                for g in range(n_ga_iterations):
                    train_idx = np.random.choice(nsamples, sample_size, replace=False)
                    eval_idx = np.random.choice(X_val.shape[0], sample_size, replace=False)
                    if nn == 2:
                        features, f = ga_iteration(kernel, penalty, features, X_tr[train_idx, :], B_tr[train_idx], X_val[eval_idx, :], B_val[eval_idx])
                    else:
                        features, f = ga_iteration(kernel, penalty, features, X_tr[train_idx, :], Y_tr[train_idx], X_val[eval_idx, :], Y_val[eval_idx])
                    print(g, np.max(f), np.sum(features, axis=1))
                idx = np.where(features[-1, :] == 1)[0]
                model = BaggingClassifier(SVC(kernel=kernel, C=penalty, cache_size=4096, verbose=1), n_estimators=10, max_samples=0.1, n_jobs=-1)
                if nn == 2:
                    model.fit(X_tr[:, idx], B_tr)
                    score = model.score(X_te[:, idx], B_te)
                else:
                    model.fit(X_tr[:, idx], Y_tr)
                    P_te = model.predict(X_te[:, idx])
                    P_te[P_te > 0] = 1
                    score = len(np.where(P_te == B_te)[0]) / len(P_te)
                msd = model_save_dir.format(kernel, penalty, nn)
                if not osp.exists(msd):
                    os.mkdir(msd)
                dump(model, osp.join(msd, model_checkpoint_file))
                line = [str(score)]
                for i in idx:
                    line.append(str(i))
                with open(osp.join(msd, model_stats_file), 'w') as f:
                    f.write(','.join(line))