import argparse
import logging
from typing import Tuple
from deepdiff import DeepDiff
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import pprint
from concurrent.futures import ThreadPoolExecutor
import os


def diff_cveid(args: Tuple[str, str, str]):
    session = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=1,
                    status_forcelist=[503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))

    # Endpoint
    # /cves/:family/:release/:id
    try:
        response_old = requests.get(
            f'http://127.0.0.1:1325/cves/{args[0]}/{args[1]}/{args[2]}', timeout=(10.0, 10.0)).json()
        response_new = requests.get(
            f'http://127.0.0.1:1326/cves/{args[0]}/{args[1]}/{args[2]}', timeout=(10.0, 10.0)).json()
    except requests.ConnectionError as e:
        logger.error(f'Failed to Connection..., err: {e}')
        raise
    except Exception as e:
        logger.error(f'Failed to GET request..., err: {e}')
        raise

    diff = DeepDiff(response_old, response_new, ignore_order=True)
    if diff != {}:
        logger.warning(
            f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({args[2]: diff}, indent=2)}')


def diff_package(args: Tuple[str, str, str]):
    # Endpoint
    # /packs/:family/:release/:pack
    raise NotImplementedError


def diff_response(args: Tuple[str, str, str, str]):
    try:
        if args[0] == 'cveid':
            diff_cveid((args[1], args[2], args[3]))
        if args[0] == 'package':
            diff_package((args[1], args[2], args[3]))
    except Exception:
        exit(1)


parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['cveid', 'package'],
                    help='Specify the mode to test.')
parser.add_argument('ostype', choices=['alpine', 'amazon', 'debian', 'oracle', 'redhat', 'suse', 'ubuntu'],
                    help='Specify the OS to be started in server mode when testing.')
parser.add_argument('release', nargs='+',
                    help='Specify the Release Version to be started in server mode when testing.')
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
    f'start server mode test(mode: {args.mode}, os: {args.ostype}, release: {args.release})')

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
elif args.ostype in ["alpine", "amazon", "suse", "oracle"]:
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
        with ThreadPoolExecutor() as executor:
            ins = ((args.mode, args.ostype, relVer, e) for e in list)
            executor.map(diff_response, ins)
