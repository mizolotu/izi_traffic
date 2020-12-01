import sys, pickle, pandas
import os.path as osp
import numpy as np

from data_proc import find_data_files

def std_data(X, xmin, xmax):
    nsamples = X.shape[0]
    X = (X - np.ones((nsamples, 1)).dot(xmin.reshape(1, -1))) / np.ones((nsamples, 1)).dot((xmax - xmin).reshape(1, -1))
    return X

if __name__ == '__main__':


    # dataset dirs and files

    dir = sys.argv[1]
    subdirs = sys.argv[2].split(',')
    subnets = sys.argv[3].split(',')
    stat_file = osp.join(dir, 'stats.pkl')
    with open(stat_file, 'rb') as f:
        stats = pickle.load(f)
    feature_inds = np.where(stats[4][:-1] > 0)[0]
    print(feature_inds)
    files = []
    for subdir in subdirs:
        files.extend(find_data_files(osp.join(dir, subdir)))

    # select files for the subnets specified

    files_selected = []
    for file in files:
        for subnet in subnets:
            if subnet in file:
                files_selected.append(file)
    print('Selected {0} files out of {1}'.format(len(files_selected), len(files)))

    # generate dataset

    x = None
    y = None
    for fi,f in enumerate(files_selected):
        print(fi / len(files_selected), f)
        p = pandas.read_csv(f, delimiter=',', header=None)
        v = p.values[:, 1:]  # first column corresponds to flow ids
        v = np.array(v, dtype=float)
        if x is not None and y is not None:
            x = np.vstack([x, std_data(v[:, feature_inds], stats[1][feature_inds], stats[2][feature_inds])])
            y = np.hstack([y, v[:, -1]])
        else:
            x = std_data(v[:, feature_inds], stats[1][feature_inds], stats[2][feature_inds])
            y = v[:, -1]
        print(x.shape, y.shape, sys.getsizeof(x) / (1024**3), len(np.where(y > 0)[0]))
    size = sys.getsizeof(x)
    maxsize = 4e9
    nchunks = int(size // maxsize) + 1
    nsamples = x.shape[0]
    chunk_size = nsamples // nchunks
    for i in range(nchunks):
        if i == nchunks - 1:
            idx = np.arange(i * chunk_size, nsamples)
        else:
            idx = np.arange((i - 1) * chunk_size, i * chunk_size)
        print(len(idx))
        x_chunk = x[idx, :]
        y_chunk = y[idx]
        with open(osp.join(dir, 'flows{0}.pkl'.format(i)), 'wb') as f:
            pickle.dump(np.hstack([x_chunk, y_chunk.reshape(-1, 1)]), f)