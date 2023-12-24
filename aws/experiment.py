#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: with p; [ boto3 botocore ])"

import os
import re
import json
from utils import *
from config import *
from aws import *

def experiment(trial, repetitions, timeout, prob):
    ec2 = EC2Instance(trial)
    num_nodes = sum([len(i) for i in ec2.instances.values()])

    trial_dir = f"{BENCH_RESULT_DIR}/{trial}"
    os.makedirs(trial_dir, exist_ok=True)
    file_name =  f"{trial_dir}/{trial}_n_{num_nodes}"
    if prob:
        file_name += f"_p_{prob.replace('/', '_')}"
    file_name += ".json"

    with open(file_name, "x") as f:
        outputs = {}
        for i in range(0, repetitions):
            print(f"Experiment {i}...")
            cmd = "cli run -c node.cfg -s partial"
            if prob:
                cmd += f" -p '{prob}'"
            print(cmd)
            outputs[i] = ec2.run_commands([cmd], max_wait_sec=timeout, output=True) 

        data = {
                "trial": trial,
                "probability": prob,
                "timeout": timeout,
                "regions": REGIONS,
                "instance_type": INSTANCE_TYPE,
                "num_nodes": num_nodes,
                "outputs": outputs,
                }
        json_data = json.dumps(data, indent=4)
        f.write(json_data)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        bail(f"{sys.argv[0]} [TRIAL] [REPETITIONS] [TIMEOUT] <PROBABILITY>")

    prob = None
    if len(sys.argv) == 5:
        prob = sys.argv[4]
        if not re.fullmatch(r"\d+/\d+", prob):
            bail(f"PROBABILIY {prob} is not a fraction!")
    try:
        repetitions = int(sys.argv[2])
    except ValueError:
            bail(f"REPETITIONS = {sys.argv[2]} is not an integer")
    try:
        timeout = int(sys.argv[3])
    except ValueError:
            bail(f"TIMEOUT = {sys.argv[3]} is not an integer")

    experiment(sys.argv[1], repetitions, timeout, prob=prob)
