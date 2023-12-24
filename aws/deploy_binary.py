#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: with p; [ boto3 botocore ])"

import tempfile
from utils import *
from config import *
from aws import *


def build_and_deploy_binary(trial):
    bucket = S3Bucket(trial)
    ec2 = EC2Instance(trial)
    with tempfile.TemporaryDirectory() as tmpdir:
        out_link = f"{tmpdir}/{PROJECT}"
        pkg_path, hash = build_pkg(out_link)
        bucket.upload_file(pkg_path, PKG_NAME)

    deployed_instances = ec2.instances_filtered("deployed_version", hash)
    to_deploy = {}
    to_deploy_count = 0
    for region in REGIONS.keys():
        deployed_ids = set(map_to_id(deployed_instances[region]))
        to_deploy[region] = [i for i in ec2.instances[region] if i.id not in deployed_ids]
        to_deploy_count += len(to_deploy[region])

    print(f"Deploying to {to_deploy_count}...")
    if to_deploy:
        ec2.run_commands([
            f"aws s3 cp s3://{bucket.name}/{PKG_NAME} {PKG_NAME}", 
            f"yum -y localinstall {PKG_NAME}"
            ], instances=to_deploy)
        ec2.tag(to_deploy, "deployed_version", hash)
    print(f"Deployed {PROJECT} version {hash}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        bail(f"{sys.argv[0]} [TRIAL]")
    trial = sys.argv[1]
    build_and_deploy_binary(trial)

