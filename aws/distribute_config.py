#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: with p; [ boto3 botocore ])"

import tempfile
import subprocess
from utils import *
from config import *
from aws import *


def distribute_config(trial):
    bucket = S3Bucket(trial)
    ec2 = EC2Instance(trial)
    ips = f":{ACSS_PORT}\n".join(ec2.get_ips().values()) + f":{ACSS_PORT}"
    ips = ips.encode()
    config_archive = f"configs.tar.gz"
    with tempfile.TemporaryDirectory() as tmpdir:
        binary = f"{tmpdir}/{PROJECT}"
        config_dir = f"{tmpdir}/config"
        config_archive_path = f"{tmpdir}/{config_archive}"
        build_binary(binary)
        try:
            subprocess.run(f"mkdir {config_dir}", shell=True, capture_output=True, check=True)
            subprocess.run(f"cd {tmpdir}; ./{PROJECT} generate -i -d {config_dir}", input=ips, shell=True, capture_output=True, check=True)
            subprocess.run(f"cd {tmpdir}; tar -czf {config_archive_path} config", shell=True, capture_output=True, check=True)
            print("Done generating.")
            bucket.upload_file(config_archive_path, config_archive)
            print("Done uploading.")
        except subprocess.CalledProcessError as e:
            bail(f"Generating config failed with exit code {e.returncode}:\n{e.stdout}\n{e.stderr}")
    ec2.run_commands([f"aws s3 cp s3://{bucket.name}/{config_archive} {config_archive}",
                      f'tar -xzf {config_archive}',
                      f'bash -c "mv config/$(curl https://checkip.amazonaws.com).cfg node.cfg"'], wait_sec=8)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        bail(f"{sys.argv[0]} [TRIAL]")
    trial = sys.argv[1]
    distribute_config(trial)
