# Test Script For goval-dictionary
Documentation on testing for developers

## Getting Started
```terminal
$ pip install -r requirements.txt
```

## Run test
Use `127.0.0.1:1325` and `127.0.0.1:1326` to diff the server mode between the latest tag and your working branch.

If you have prepared the two addresses yourself, you can use the following Python script.
```terminal
$ python diff_server_mode.py debian --help
usage: diff_server_mode.py [-h] [--arch {x86_64,i386,ia64,i686,sparc64,aarch64,noarch}]
                           [--suse-type {opensuse,opensuse.leap,suse.linux.enterprise.server,suse.linux.enterprise.desktop}]
                           [--sample-rate SAMPLE_RATE] [--debug | --no-debug]
                           {cveid,package} {alpine,amazon,debian,oracle,redhat,suse,ubuntu} release [release ...]

positional arguments:
  {cveid,package}       Specify the mode to test.
  {alpine,amazon,debian,oracle,redhat,suse,ubuntu}
                        Specify the OS to be started in server mode when testing.
  release               Specify the Release Version to be started in server mode when testing.

optional arguments:
  -h, --help            show this help message and exit
  --arch {x86_64,i386,ia64,i686,sparc64,aarch64,noarch}
                        Specify the Architecture to be started in server mode when testing.
  --suse-type {opensuse,opensuse.leap,suse.linux.enterprise.server,suse.linux.enterprise.desktop}
                        Specify the SUSE type to be started in server mode when testing.
  --sample-rate SAMPLE_RATE
                        Adjust the rate of data used for testing (len(test_data) * sample_rate)
  --debug, --no-debug   print debug message
```

[GNUmakefile](../GNUmakefile) has some tasks for testing.  
Please run it in the top directory of the goval-dictionary repository.

- build-integration: create the goval-dictionary binaries needed for testing
- clean-integration: delete the goval-dictionary process, binary, and docker container used in the test
- fetch-rdb: fetch data for RDB for testing
- fetch-redis: fetch data for Redis for testing
- diff-cveid: Run tests for CVE ID in server mode
- diff-package: Run tests for Package in server mode
- diff-server-rdb: take the result difference of server mode using RDB
- diff-server-redis: take the result difference of server mode using Redis
- diff-server-rdb-redis: take the difference in server mode results between RDB and Redis
