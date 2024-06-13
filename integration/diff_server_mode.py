import argparse
import logging
from typing import Tuple
from deepdiff import DeepDiff
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import quote
import pprint
from concurrent.futures import ThreadPoolExecutor
import os
import random
import math
import json
import shutil
import time


def diff_response(args: Tuple[str, str, str, str, str]):
    # Endpoint
    # /cves/:family/:release/:id
    # /packs/:family/:release/:pack

    path = ''
    if args[0] == 'cveid':
        path = f'cves/{args[1]}/{args[3]}/{args[4]}'
    if args[0] == 'package':
        path = f'packs/{args[1]}/{args[3]}/{args[4]}'

    if args[2] != "":
        path = f'{path}/{args[2]}'

    session = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=1,
                    status_forcelist=[503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))

    try:
        response_old = requests.get(
            f'http://127.0.0.1:1325/{path}', timeout=(3.0, 10.0)).json()
        response_new = requests.get(
            f'http://127.0.0.1:1326/{path}', timeout=(3.0, 10.0)).json()
    except requests.ConnectionError as e:
        logger.error(
            f'Failed to Connection..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
        exit(1)
    except requests.ReadTimeout as e:
        logger.warning(
            f'Failed to ReadTimeout..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
    except Exception as e:
        logger.error(
            f'Failed to GET request..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
        exit(1)

    diff = DeepDiff(response_old, response_new, ignore_order=True)
    if diff != {}:
        logger.warning(
            f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"args": args, "path": path}, indent=2)}')

        diff_path = f'integration/diff/{args[1]}/{args[3]}/{args[0]}/{args[4]}'
        if args[2] != "":
            diff_path = f'integration/diff/{args[1]}/{args[3]}({args[2]})/{args[0]}/{args[4]}'

        with open(f'{diff_path}.old', 'w') as w:
            w.write(json.dumps(response_old, indent=4))
        with open(f'{diff_path}.new', 'w') as w:
            w.write(json.dumps(response_new, indent=4))


parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['cveid', 'package'],
                    help='Specify the mode to test.')
parser.add_argument('ostype', choices=['alpine', 'amazon', 'debian', 'oracle', 'redhat', 'suse', 'ubuntu', 'fedora'],
                    help='Specify the OS to be started in server mode when testing.')
parser.add_argument('--arch', default="", choices=['x86_64', 'i386', 'ia64', 'i686', 'sparc64', 'aarch64', 'noarch'],
                    help='Specify the Architecture to be started in server mode when testing.')
parser.add_argument('release', nargs='+',
                    help='Specify the Release Version to be started in server mode when testing.')
parser.add_argument('--suse-type', default="", choices=['opensuse', 'opensuse.leap', 'suse.linux.enterprise.server', 'suse.linux.enterprise.desktop'],
                    help='Specify the SUSE type to be started in server mode when testing.')
parser.add_argument("--sample-rate", type=float, default=0.01,
                    help="Adjust the rate of data used for testing (len(test_data) * sample_rate)")
parser.add_argument(
    '--debug', action=argparse.BooleanOptionalAction, help='print debug message')
args = parser.parse_args()

logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler()

if args.debug:
    logger.setLevel(logging.DEBUG)
    stream_handler.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
    stream_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    '%(levelname)s[%(asctime)s] %(message)s', "%m-%d|%H:%M:%S")
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

if args.ostype == "suse":
    logger.info(
        f'start server mode test(mode: {args.mode}, os: {args.suse_type}, arch: {args.arch}, release: {args.release})')
else:
    logger.info(
        f'start server mode test(mode: {args.mode}, os: {args.ostype}, arch: {args.arch}, release: {args.release})')

logger.info('check the communication with the server')
for i in range(5):
    try:
        if requests.get('http://127.0.0.1:1325/health').status_code == requests.codes.ok and requests.get('http://127.0.0.1:1326/health').status_code == requests.codes.ok:
            logger.info('communication with the server has been confirmed')
            break
    except Exception:
        pass
    time.sleep(1)
else:
    logger.error('Failed to communicate with server')
    exit(1)

if args.ostype == 'debian':
    if len(list(set(args.release) - set(['7', '8', '9', '10', '11', '12']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'ubuntu':
    if len(list(set(args.release) - set(['14.04', '16.04', '18.04', '19.10', '20.04', '20.10', '21.04', '21.10', '22.04', '22.10', '23.04', '23.10', '24.04']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'redhat':
    if len(list(set(args.release) - set(['5', '6', '7', '8', '9']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'oracle':
    if len(list(set(args.release) - set(['5', '6', '7', '8', '9']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'amazon':
    if len(list(set(args.release) - set(['1', '2', '2022', '2023']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'alpine':
    if len(list(set(args.release) - set(['3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14', '3.15', '3.16', '3.17', '3.18', '3.19', '3.20']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == "suse":
    if args.suse_type == 'opensuse':
        if len(list(set(args.release) - set(['10.2', '10.3', '11.0', '11.1', '11.2', '11.3', '11.4', '12.1', '12.2', '12.3', '13.1', '13.2', 'tumbleweed']))) > 0:
            logger.error(
                f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
            raise NotImplementedError
    elif args.suse_type == 'opensuse.leap':
        if len(list(set(args.release) - set(['42.1', '42.2', '42.3', '15.0', '15.1', '15.2', '15.3', '15.4', '15.5', '15.6']))) > 0:
            logger.error(
                f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
            raise NotImplementedError
    elif args.suse_type == 'suse.linux.enterprise.server':
        if len(list(set(args.release) - set(['9', '10', '11', '12', '15']))) > 0:
            logger.error(
                f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
            raise NotImplementedError
    elif args.suse_type == 'suse.linux.enterprise.desktop':
        if len(list(set(args.release) - set(['10', '11', '12', '15']))) > 0:
            logger.error(
                f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
            raise NotImplementedError
elif args.ostype == 'fedora':
    if len(list(set(args.release) - set(['32', '33', '34', '35', '36', '37', '38', '39', '40']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
else:
    logger.error(
        f'Failed to diff_response..., err: This OS type({args[1]}) does not support test mode(cveid)')
    raise NotImplementedError

ostype = args.ostype
if args.ostype == "suse":
    ostype = args.suse_type

for relVer in args.release:
    list_path = None
    if args.mode == 'cveid':
        if args.ostype == "suse":
            list_path = f"integration/cveid/{args.ostype}/{args.suse_type}_{relVer}.txt"
        else:
            list_path = f"integration/cveid/{args.ostype}/{args.ostype}_{relVer}.txt"
    if args.mode == 'package':
        if args.ostype == "suse":
            list_path = f"integration/package/{args.ostype}/{args.suse_type}_{relVer}.txt"
        else:
            list_path = f"integration/package/{args.ostype}/{args.ostype}_{relVer}.txt"

    if not os.path.isfile(list_path):
        logger.error(f'Failed to find list path..., list_path: {list_path}')
        exit(1)

    diff_path = f'integration/diff/{ostype}/{relVer}/{args.mode}'
    if args.arch != "":
        diff_path = f'integration/diff/{ostype}/{relVer}({args.arch})/{args.mode}'
    if os.path.exists(diff_path):
        shutil.rmtree(diff_path)
    os.makedirs(diff_path, exist_ok=True)

    with open(list_path) as f:
        list = [s.strip() for s in f.readlines()]
        list = random.sample(list, math.ceil(len(list) * args.sample_rate))
        with ThreadPoolExecutor() as executor:
            ins = ((args.mode, ostype, args.arch, relVer, quote(e))
                   for e in list)
            executor.map(diff_response, ins)
