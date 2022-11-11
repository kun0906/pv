""" Common functions and utilities

"""
# Author: kun.bj@outlook.com

import os
import pickle
import time
from datetime import datetime

import numpy as np


def check_dir(dir_path):
    # if os.path.isfile(dir_path):
    # 	dir_path = os.path.dirname(dir_path)

    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def dump(data, out_file):
    out_dir = os.path.dirname(out_file)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    with open(out_file, 'wb') as out:
        pickle.dump(data, out)


def timer(func):
    # This function shows the execution time of the passed function
    def wrap_func(*args, **kwargs):
        t1 = time.time()
        print(f'{func.__name__}() starts at {datetime.now()}')
        result = func(*args, **kwargs)
        t2 = time.time()
        print(f'{func.__name__}() ends at {datetime.now()}')
        print(f'Function {func.__name__!r} executed in {(t2 - t1):.4f}s')
        return result

    return wrap_func


def fmt(data, precision=3):
    def _format(data2):
        if type(data2) == np.array or type(data2) == list:
            res = np.asarray([_format(v) for v in data2])
        else:
            res = f'{data2:.{precision}f}'

        return res

    return _format(data)


@timer
def animate(figs, out_file='all.mp4'):
	""" MacOS cannot stop the gif loop, so you can view it in Browser (e.g., Chrome).

	Parameters
	----------
	figs
	out_file

	Returns
	-------

	"""
	if len(figs) == 0: return
	print(figs)
	import imageio, PIL
	# figs = [imageio.v2.imread(f) for f in figs]
	# kwargs = {'duration': 1, 'loop': 1}
	# imageio.mimsave(out_file, images, format='GIF', **kwargs)  # each image 0.5s = duration/n_imgs
	images = []
	for i, f in enumerate(figs):
		if 'png' not in f: continue
		im = imageio.v2.imread(f)  # RGBA
		if i == 0:
			shape = im.shape[:2][::-1]
		# print(im.shape)
		im = PIL.Image.fromarray(im).resize(shape)  # (width, height)
		images.append(im)
	kwargs = {'fps': 1}
	imageio.v2.mimsave(out_file, images, format='mp4', **kwargs)  # each image 0.5s = duration/n_imgs

	return out_file
