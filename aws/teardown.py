#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: [p.boto3])"

from utils import *
from aws import *

def teardown(trial):
    ec2 = EC2Instance(trial)
    ec2.terminate()
    ec2.delete_security_groups()
    S3Bucket(trial).delete()
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        bail(f"{sys.argv[0]} [TRIAL]")
    teardown(sys.argv[1])
