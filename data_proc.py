import os, pandas, pickle, sys
import os.path as osp
import numpy as np

from sys import getsizeof

def find_data_files(dir, prefix='', postfix=''):
    data_files = []
    for f in os.listdir(dir):
        fp = osp.join(dir, f)
        if osp.isfile(fp) and fp.startswith(osp.join(dir, prefix)) and fp.endswith(postfix):
            data_files.append(fp)
    return data_files

def extract_values(data_file, minus_ids=[67, 68]):
    p = pandas.read_csv(data_file, delimiter=',', skiprows=1)
    v = p.values
    if '20-02-2018' in data_file:
        v = v[:, 4:]

    # remove header line in the middle of the data

    idx = np.where(v[:, 1] == 'Protocol')[0]
    if len(idx) > 0:
        v = np.delete(v, idx, 0)
        print('{0} rows have been deleted'.format(len(idx)))

    # look for http data

    http_idx = np.where((v[:, 0] == 80) | (v[:, 0] == 443))[0]

    # substitute minus ones with zeroes in columns minus_ids

    for mi in minus_ids:
        v[np.where(v[:, mi] == -1)[0], mi] = 0

    # stack values

    values = np.hstack([v[:, 1:2].astype(float), v[:, 3:-1].astype(float)])
    labels = v[:, -1]

    # remove lines with nan and inf

    finites = np.all(np.isfinite(values), axis=1)
    idx = np.where(finites == False)[0]
    if len(idx) > 0:
        print('{0} non-finite rows found'.format(len(idx)))
        values = np.delete(values, idx, 0)
        labels = np.delete(labels, idx)

    # remove lines with negative values

    negatives = np.all(values >= 0, axis=1)
    idx = np.where(negatives == False)[0]
    if len(idx) > 0:
        print('{0} non-positive rows found'.format(len(idx)))
        values = np.delete(values, idx, 0)
        labels = np.delete(labels, idx)

    print(data_file, values.shape, labels.shape, getsizeof(values), len(http_idx))

    idx = np.where(labels == 'DoS attacks-SlowHTTPTest')[0]
    print(np.mean(values[idx, :10], axis=0))
    print(np.min(values[idx, :10], axis=0))
    print(np.max(values[idx, :10], axis=0))

    return values, labels

def one_hot_encode(values, categories):
    value_categories = np.unique(values)
    oh = np.zeros((values.shape[0], len(categories)))
    for vc in value_categories:
        c_idx = categories.index(vc)
        idx = np.where(values == vc)[0]
        oh[idx, c_idx] = 1
    return oh

def load_dataset(data_dir, data_file_prefix, data_file_postfix, tvt=[0.4,0.2,0.4]):
    data_files = find_data_files(data_dir, data_file_prefix, data_file_postfix)
    X, Y = None, None
    for data_file in data_files[:3]: # remove [:1] later
        print(data_file)
        with open(data_file, 'rb') as f:
            XY = pickle.load(f)
            nfeatures = XY.shape[1]
            if X is not None and Y is not None:
                X = np.vstack([X, XY[:, :nfeatures-1]])
                Y = np.hstack([Y, XY[:, -1]])
            else:
                X = XY[:, :nfeatures-1]
                Y = XY[:, -1]

    # separate to train, validation and test chunks

    L = np.unique(Y)
    nlabels = len(L)
    for i in range(nlabels):
        print(L[i], len(np.where(Y == L[i])[0]))
    Yu = np.zeros_like(Y)
    for i in range(nlabels):
        Yu[Y == L[i]] = i
    Y = Yu.copy()
    for i in range(nlabels):
        print(i, len(np.where(Y == i)[0]))
    ready = False
    while not ready:
        idx = np.arange(X.shape[0])
        np.random.shuffle(idx)
        X = X[idx, :]
        Y = Y[idx]
        X_tr = X[:int(tvt[0] * X.shape[0]), :]
        Y_tr = Y[:int(tvt[0] * X.shape[0])]
        X_val = X[int(tvt[0] * X.shape[0]) : int(np.sum(tvt[:2]) * X.shape[0]), :]
        Y_val = Y[int(tvt[0] * X.shape[0]) : int(np.sum(tvt[:2]) * X.shape[0])]
        X_te = X[int(np.sum(tvt[:2]) * X.shape[0]) : int(np.sum(tvt) * X.shape[0]), :]
        Y_te = Y[int(np.sum(tvt[:2]) * X.shape[0]) : int(np.sum(tvt) * X.shape[0])]
        if len(np.unique(Y_tr)) == nlabels and len(np.unique(Y_val)) == nlabels and len(np.unique(Y_te)) == nlabels:
            ready = True
        print(np.unique(Y_tr), np.unique(Y_val), np.unique(Y_te))
    return X_tr, Y_tr, X_val, Y_val, X_te, Y_te

if __name__ == '__main__':

    # args

    data_dir = sys.argv[1]
    n_data_files = int(sys.argv[2])
    tasks = sys.argv[3:]

    # find data files

    data_files = find_data_files(data_dir, prefix='Friday-16-02-2018', postfix='.csv')
    stats_file = 'stats.pkl'
    dataset_file = 'data{0}.pkl'

    # lists for categorical features and labels

    uprotos = []
    nprotos = []
    ulabels = []
    nlabels = []

    # min, max, mean and std

    X_min = None
    X_max = None
    X_mean = None
    X_std = None
    N = 0

    # collect stats

    if 'stats' in tasks:
        stats = []
        pp = []
        labels = []
        for data_file in data_files[0:n_data_files]:
            values, labels = extract_values(data_file)
            for label in np.unique(labels):
                nl = len(np.where(labels == label)[0])
                if label not in ulabels:
                    ulabels.append(label)
                    nlabels.append(nl)
                else:
                    nlabels[ulabels.index(label)] += nl
            for proto in np.unique(values[:, 0]):
                npr = len(np.where(values[:, 0] == proto)[0])
                if proto not in uprotos:
                    uprotos.append(proto)
                    nprotos.append(npr)
                else:
                    nprotos[uprotos.index(proto)] += npr
            for l,nl in zip(ulabels, nlabels):
                print(l ,nl)
            for p,npr in zip(uprotos, nprotos):
                print(p ,npr)

            x_min = np.min(values[:, 1:], axis=0)
            x_max = np.max(values[:, 1:], axis=0)
            x_mean = np.mean(values[:, 1:], axis=0)
            x_std = np.std(values[:, 1:], axis=0)
            n = values.shape[0]
            if X_min is None:
                X_min = x_min
            else:
                X_min = np.min(np.vstack([x_min, X_min]), axis=0)
            if X_max is None:
                X_max = x_max
            else:
                X_max = np.max(np.vstack([x_max, X_max]), axis=0)
            if X_mean is None and X_std is None:
                X_mean = x_mean
                X_std = x_std
                N = n
            else:
                mu = (N * X_mean + n * x_mean) / (N + n)
                D = X_mean - mu
                d = x_mean - mu
                X_std = np.sqrt((N * (D**2 + X_std**2) + n * (d**2 + x_std**2)) / (N + n))
                N = N + n
                X_mean = mu
            with open(osp.join(data_dir, stats_file), 'wb') as f:
                pickle.dump(
                    (ulabels, uprotos, N, X_min, X_max, X_mean, X_std), f
                )

    if 'dataset' in tasks:

        # load stats

        with open(osp.join(data_dir, stats_file), 'rb') as f:
            labels, protos, N, X_min, X_max, X_mean, X_std = pickle.load(f)

        # extract data

        x = []
        y = []
        for data_file in data_files[0:n_data_files]:
            print(data_file)
            v, l = extract_values(data_file)
            x.append(np.hstack([
                one_hot_encode(v[:, 0], protos),
                (v[:, 1:] - np.ones((len(v), 1)).dot(X_mean.reshape(1, -1))) / (1e-10 + np.ones((len(v), 1)).dot(X_std.reshape(1, -1)))
            ]))
            y.append(one_hot_encode(l, labels))

        # save dataset

        x = np.vstack(x)
        y = np.vstack(y)
        xy = np.hstack([x, y])
        print('Dataset shape: {0}, size on disk: {1}'.format(xy.shape, getsizeof(xy)))
        nfiles = 4
        idx = np.arange(0, xy.shape[0], xy.shape[0] // nfiles)
        for i in range(nfiles):
            fname = osp.join(data_dir, dataset_file.format(i))
            if i < nfiles - 1:
                idx_i = np.arange(idx[i], idx[i+1])
            else:
                idx_i = np.arange(idx[i], xy.shape[0])
            with open(fname, 'wb') as f:
                pickle.dump(xy[idx_i, :], f)