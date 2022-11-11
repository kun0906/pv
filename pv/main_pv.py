"""

	https://github.com/KimiNewt/pyshark

"""
import heapq
import os.path
import pickle
import shutil

import numpy as np
import pyshark
from PIL import Image

from utils.common import check_dir, animate


def pkt2img(pkt, img_file='.png', H=100, W=100):
	check_dir(os.path.dirname(img_file))

	if 'tcp' in pkt:
		# https://stackoverflow.com/questions/34441342/check-if-object-is-in-list-given-by-pyshark
		# payload = pkt.tcp.payload: could lead mac dead
		payload = pkt.tcp.get_field('payload')
	elif 'udp' in pkt:
		# payload = pkt.udp.payload: could lead mac dead
		payload = pkt.udp.get_field('payload')
	else:
		return
	if payload is None: return

	try:
		data = str(payload).split(':')
		print(data)
		data = [int(v, 16) for v in data]
		n = len(data)
		N = H * W
		# append zero or cut off
		if n < N:
			data = data + [0] * (N - n)
		elif n > N:
			data = data[:N]
		else:
			pass
		data = np.array(data)
		data = data.reshape((H, W))
		print(data.shape, data)
	except Exception as e:
		print(f'Error: {e}, {img_file}')
		return
	im = Image.fromarray(data, mode="L")  # L:Luminance
	with open(img_file, 'wb') as f:
		im.save(f, subsampling=0, quality=100)


def pkts2img(pkts, five_tuple, img_file='.png', H=100, W=100):
	check_dir(os.path.dirname(img_file))

	payloads = []
	for pkt in pkts:
		if 'tcp' in pkt:
			# https://stackoverflow.com/questions/34441342/check-if-object-is-in-list-given-by-pyshark
			# payload = pkt.tcp.payload: could lead mac dead
			payload = pkt.tcp.get_field('payload')
		elif 'udp' in pkt:
			# payload = pkt.udp.payload: could lead mac dead
			payload = pkt.udp.get_field('payload')
		else:
			continue
		if payload is None: continue
		payloads.append(str(payload))

	if len(payloads) == 0: return
	payloads = ':'.join(payloads)
	try:
		data = str(payloads).split(':')
		# print(data)
		data = [int(v, 16) for v in data]
		n = len(data)
		N = H * W
		# append zero or cut off
		if n < N:
			data = data + [0] * (N - n)
		elif n > N:
			data = data[:N]
		else:
			pass
		data = np.array(data)
		data = data.reshape((H, W))
		print(five_tuple, data.shape)
	except Exception as e:
		print(f'Error: {e}, {img_file}')
		return
	im = Image.fromarray(data, mode="L")
	with open(img_file, 'wb') as f:
		im.save(f)


def main():
	out_dir = 'out'
	if os.path.exists(out_dir):
		shutil.rmtree(out_dir)
	check_dir(out_dir)
	capture = pyshark.LiveCapture(interface='en0')
	i = 0
	flow_buf = {}
	h = []
	TIMEOUT = 10  # 600s
	pkts = []
	for pkt in capture.sniff_continuously(packet_count=5000):
		pkts.append(pkt)
		i += 1
		# if i % 100 == 0: print(f'{i}th packet just arrived:', pkt)
		if 'ip' not in pkt: continue
		ip = pkt.ip
		if 'tcp' in pkt:
			key = ','.join([str(ip.src), str(ip.dst), str(pkt.tcp.srcport), str(pkt.tcp.dstport), 'tcp'])
		elif 'udp' in pkt:
			key = ','.join([str(ip.src), str(ip.dst), str(pkt.udp.srcport), str(pkt.udp.dstport), 'udp'])
		else:
			print(f'{i}-th packet: {pkt.layers}')
			continue
		if key not in flow_buf:
			flow_buf[key] = [pkt]
		else:
			flow_buf[key].append(pkt)

		dur_flow = float(flow_buf[key][-1].sniff_timestamp) - float(flow_buf[key][0].sniff_timestamp)
		print(i, dur_flow)
		heapq.heappush(h, (-dur_flow, key))
		dur_flow, key = h[0]  # check the top of the heap
		if -dur_flow >= TIMEOUT:
			dur_flow, key = heapq.heappop(h)
			if key in flow_buf.keys():
				img_file = os.path.join(out_dir, f'{key}-{len(flow_buf[key])}.png')
				pkts2img(flow_buf[key], key, img_file)
				del flow_buf[key]  # delete the old flow

	# https://github.com/secdev/scapy/issues/2193
	pcap_file = os.path.join(out_dir, f'n_{i}.pkl')
	# from scapy.utils import wrpcap
	# wrpcap(pcap_file, pkts) # TypeError: cannot convert 'XmlLayer' object to bytes
	with open(pcap_file, 'wb') as f:
		pickle.dump(pkts, f)
	print(f'Total packets: {i}: {pcap_file}.')

	out_file = os.path.join(out_dir, 'all.mp4')
	imgs = sorted([os.path.join(out_dir, f) for f in os.listdir(out_dir) if f[-4:] == '.png'])
	animate(imgs, out_file)


if __name__ == '__main__':
	main()
