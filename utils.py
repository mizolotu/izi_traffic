import numpy as np

def restore_tcp(x, xmin, xmax):
    x = np.clip(x, xmin, xmax)
    p = x * (xmax - xmin) + xmin
    iat = p[0] - xmin[0]
    psize = int(p[1])
    wsize = int(p[2])
    return iat, psize, wsize

def restore_http(x, xmin, xmax, psize):
    x = np.clip(x, xmin, xmax)
    p = x * (xmax - xmin) + xmin
    payload = np.random.choice(256, psize, p=x)
    return
