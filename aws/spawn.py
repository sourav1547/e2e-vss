#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: with p; [ boto3 botocore ])"

import time
import sys
from config import *
from utils import *
from aws import *


def main(trial, count, setup_command):
    ec2 = EC2Instance(trial)
    ec2.spawn_instances(count, setup_command=setup_command)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        bail(f"{sys.argv[0]} [TRIAL] [NODE_COUNT] <SETUP_COMMAND>")
    try:
        node_count = int(sys.argv[2])
        setup_command = "" if len(sys.argv) < 4 else sys.argv[3]
        if node_count % len(REGIONS) != 0:
            bail("NODE_COUNT not a multiple of the region count")
        main(sys.argv[1], node_count, setup_command)
    except ValueError:
        bail(f"NODE_COUNT = {sys.argv[1]} is not an integer")
