import tflite_runtime.interpreter as tflite
import argparse as arp
import os.path as osp
import numpy as np
import json

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Test generator')
    parser.add_argument('-t', '--traffic', help='Traffic', default='80_7')
    args = parser.parse_args()

    with open(osp.join('generators', 'tcp', 'metainfo.json'), 'r') as f:
        meta = json.load(f)
    xmin = np.array(meta['xmin'])
    xmax = np.array(meta['xmax'])
    model_file = osp.join('generators', 'tcp', '{0}.tflite'.format(args.traffic))
    interpreter = tflite.Interpreter(model_path=model_file)

    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    input_shape = input_details[0]['shape']
    print(input_details[0]['shape'], input_details[1]['shape'])
    input_data = np.array(np.random.random_sample(input_shape), dtype=np.float32)

    input1 = np.array(np.random.randn(2048, 3), dtype=np.float32)
    input2 = np.array(np.vstack([
        np.hstack([np.ones((1024, 1)), np.zeros((1024, 1)), np.zeros((1024, 3)), np.ones((1024, 2)), np.zeros((1024, 3))]),
        np.hstack([np.zeros((1024, 1)), np.ones((1024, 1)), np.zeros((1024, 3)), np.ones((1024, 2)), np.zeros((1024, 3))])
    ]), dtype=np.float32)

    interpreter.set_tensor(input_details[0]['index'], input1)
    interpreter.set_tensor(input_details[1]['index'], input2)

    interpreter.invoke()
    output_data = interpreter.get_tensor(output_details[0]['index'])
    x_delta = xmax - xmin
    output_data = output_data * x_delta[None, :] + xmin[None, :]

    print(output_data)
