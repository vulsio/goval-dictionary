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


def diff_response(args: Tuple[str, str, str, str, str]):
    # Endpoint
    # /cves/:family/:release/:id
    # /packs/:family/:release/:pack

    path = ''
    if args[0] == 'cveid':
        path = f'cves/{args[1]}/{args[3]}/{args[4]}'
    if args[0] == 'package':
        path = f'packs/{args[1]}/{args[3]}/{quote(args[4])}'

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
        logger.error(f'Failed to Connection..., err: {e}')
        exit(1)
    except Exception as e:
        logger.error(f'Failed to GET request..., err: {e}')
        exit(1)

    diff = DeepDiff(response_old, response_new, ignore_order=True)
    if diff != {}:
        logger.warning(
            f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"mode": args[0], "args": args, "diff": diff}, indent=2)}')


parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['cveid', 'package'],
                    help='Specify the mode to test.')
parser.add_argument('ostype', choices=['alpine', 'amazon', 'debian', 'oracle', 'redhat', 'suse', 'ubuntu'],
                    help='Specify the OS to be started in server mode when testing.')
parser.add_argument('--arch', default="", choices=['x86_64', 'i386', 'ia64', 'i686', 'sparc64', 'aarch64', 'noarch'],
                    help='Specify the Architecture to be started in server mode when testing.')
parser.add_argument('release', nargs='+',
                    help='Specify the Release Version to be started in server mode when testing.')
parser.add_argument("--sample_rate", type=float, default=0.01,
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

logger.info(
    f'start server mode test(mode: {args.mode}, os: {args.ostype}, arch: {args.arch}, release: {args.release})')

if args.ostype == 'debian':
    if len(list(set(args.release) - set(['7', '8', '9', '10']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'ubuntu':
    if len(list(set(args.release) - set(['14', '16', '18', '19', '20']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'redhat':
    if len(list(set(args.release) - set(['5', '6', '7', '8']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'oracle':
    if len(list(set(args.release) - set(['5', '6', '7', '8']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'amazon':
    if len(list(set(args.release) - set(['1', '2']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype == 'alpine':
    if len(list(set(args.release) - set(['3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14']))) > 0:
        logger.error(
            f'Failed to diff_response..., err: This Release Version({args.release}) does not support test mode')
        raise NotImplementedError
elif args.ostype in ["suse"]:
    raise NotImplementedError
else:
    logger.error(
        f'Failed to diff_response..., err: This OS type({args[1]}) does not support test mode(cveid)')
    raise NotImplementedError

for relVer in args.release:
    list_path = None
    if args.mode == 'cveid':
        list_path = f"integration/cveid/{args.ostype}/{args.ostype}_{relVer}.txt"
    if args.mode == 'package':
        list_path = f"integration/package/{args.ostype}/{args.ostype}_{relVer}.txt"

    if not os.path.isfile(list_path):
        logger.error(f'Failed to find list path..., list_path: {list_path}')
        exit(1)

    with open(list_path) as f:
        list = [s.strip() for s in f.readlines()]
        list = random.sample(list, math.ceil(len(list) * args.sample_rate))
        with ThreadPoolExecutor() as executor:
            ins = ((args.mode, args.ostype, args.arch, relVer, e)
                   for e in list)
            executor.map(diff_response, ins)
