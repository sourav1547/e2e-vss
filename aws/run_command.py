#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: [p.boto3])"
from utils import *
from aws import *

def run_command(trial, command, timeout, node_count=None):
    ec2 = EC2Instance(trial)
    if node_count:
        if node_count > ec2.instance_count():
            bail(f"Not enough nodes! {node_count} > {ec2.instance_count()}!")
        count_per_region, remainder = divmod(node_count, len(REGIONS))
        instances_to_use = {}
        for (region, instances) in ec2.instances.items():
            if remainder > 0:
                instances_to_use[region] = instances[:count_per_region + 1]
                remainder -= 1
            else:
                instances_to_use[region] = instances[:count_per_region]
    else:
        instances_to_use = None
    for output in ec2.run_commands([command], max_wait_sec=timeout, instances=instances_to_use, output=True):
        print(output)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        bail(f"{sys.argv[0]} [TRIAL] [COMMAND] [TIMEOUT] <NODE_COUNT>")
    try:
        timeout = int(sys.argv[3])
    except ValueError:
            bail(f"NODE_COUNT = {sys.argv[3]} is not an integer")
    if len(sys.argv) > 4:
        try:
            run_command(sys.argv[1], sys.argv[2], timeout, node_count=int(sys.argv[4]))
        except ValueError:
            bail(f"NODE_COUNT = {sys.argv[3]} is not an integer")
    else:
        run_command(sys.argv[1], sys.argv[2], timeout)

