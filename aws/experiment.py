#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages(p: with p; [ boto3 botocore ])"

import os
import re
import json
from utils import *
from config import *
from aws import *
from statistics import mean 

def experiment(trial, repetitions, timeout, acss_type, deg, seed, wait_time):
    ec2 = EC2Instance(trial)
    num_nodes = sum([len(i) for i in ec2.instances.values()])

    trial_dir = f"{BENCH_RESULT_DIR}/{trial}"
    os.makedirs(trial_dir, exist_ok=True)
    file_name =  f"{trial_dir}/{trial}_n_{num_nodes}"
    if acss_type:
        file_name += f"_p_{acss_type}_{deg}_{wait_time}"
    file_name += ".json"

    partial_stats = True
    with open(file_name, "x") as f:
        outputs = {}
        stats = {}

        ad_stats = {"latency": [], "bw": [], "msg_count":[]}
        ar_stats = {"latency": [], "bw": [], "msg_count":[]}

        for i in range(0, repetitions):
            print(f"Experiment {i}...")
            cmd = "cli run -c node.cfg -s full"
            if partial_stats:
                cmd = "cli run -c node.cfg -s partial"
            if acss_type:
                cmd += f" -a '{acss_type}' -d '{deg}' -p '{int(seed)+i}' -w '{wait_time}'"
            print(cmd)
            outputs[i] = ec2.run_commands([cmd], max_wait_sec=timeout, output=True) 

            if partial_stats:
                dealer_latency = 0
                dealer_sent = 0
                dealer_count = 0

                rcv_stats = {"latency":[], "msg_count":[], "byte_sent":[]}
                for value in outputs[i]:
                    if value == "TimedOut":
                        continue 
                    data = value.split(",")
                    data = list(map(int, value.split(",")))
                    idx, byte_sent, msg_count, latency = data[0], data[1], data[2], data[3]

                    if idx == 0:
                        dealer_latency = latency
                        dealer_sent = byte_sent/2**10
                        dealer_count = msg_count
                    
                    if idx != 0:
                        rcv_stats["latency"].append(latency)
                        rcv_stats["msg_count"].append(msg_count)
                        rcv_stats["byte_sent"].append(byte_sent)
                
                rcv_avg_latency = mean(rcv_stats["latency"])
                rcv_avg_msg_count = mean(rcv_stats["msg_count"])
                rcv_avg_byte_sent = mean(rcv_stats["byte_sent"])/2**10

                dealer_count -= rcv_avg_msg_count
                dealer_sent -= rcv_avg_byte_sent

                print("")
                print(f"{'Latency:':<15}{round(dealer_latency, 2):<20}{'Dealer BW (KBytes):':<25}{round(dealer_sent, 2):<20}{'Dealer Msg Count:':<20}{round(dealer_count, 2)}")
                
                # print(f"{'Rcv Latency:':<15}{round(rcv_avg_latency, 2):<20}{'Rcv BW (KBytes):':<25}{round(rcv_avg_byte_sent, 2):<20}{'Rcv Msg Count:':<20}{round(rcv_avg_msg_count, 2)}")
                print(f"{'Rcv BW (KBytes):':<25}{round(rcv_avg_byte_sent, 2):<20}{'Rcv Msg Count:':<20}{round(rcv_avg_msg_count, 2)}")

                print("-"*50)

                dealer_stats = {
                    "Latency": round(dealer_latency, 2),
                    "Dealer BW (KBytes)": round(dealer_sent, 2),
                    "Dealer Msg Count": round(dealer_count, 2)
                }

                non_dealer_stats = {
                    # "Rcv Latency": round(rcv_avg_latency, 2),
                    "Rcv BW (KBytes)": round(rcv_avg_byte_sent, 2),
                    "Rcv Msg Count": round(rcv_avg_msg_count, 2)
                }

                stats[i] = {"dealer_stats": dealer_stats, "non_dealer_stats": non_dealer_stats}

                ad_stats["latency"].append(dealer_latency)
                ad_stats["bw"].append(dealer_sent)
                ad_stats["msg_count"].append(dealer_count)

                # ar_stats["latency"].append(rcv_avg_latency)
                ar_stats["bw"].append(rcv_avg_byte_sent)
                ar_stats["msg_count"].append(rcv_avg_msg_count)
    
        print("------------- Avergage of Average -------------")

        ad_latency = round(mean(ad_stats["latency"]), 2)
        ad_bw = round(mean(ad_stats["bw"]), 2)
        ad_msg_count = round(mean(ad_stats["msg_count"]),2)

        # ar_latency = round(mean(ar_stats["latency"]),2)
        ar_bw = round(mean(ar_stats["bw"]),2)
        ar_msg_count = round(mean(ar_stats["msg_count"]),2)


        ad_stats = {
            "Latency": ad_latency,
            "Dealer BW (KBytes)": ad_bw,
            "Dealer Msg Count": ad_msg_count
        }

        ar_stats = {
            # "Rcv Latency": ar_latency,
            "Rcv BW (KBytes)": ar_bw,
            "Rcv Msg Count": ar_msg_count
        }

        print(f"{'Latency:':<15}{ad_latency:<20}{'Dealer BW (KBytes):':<25}{ad_bw:<20}{'Dealer Msg Count:':<20}{ad_msg_count}")
        print(f"{'Rcv BW (KBytes):':<25}{ar_bw:<20}{'Rcv Msg Count:':<20}{ar_msg_count}")
        # print(f"{'Rcv Latency:':<15}{ar_latency:<20}{'Rcv BW (KBytes):':<25}{ar_bw:<20}{'Rcv Msg Count:':<20}{ar_msg_count}")
    
        data = {
                "trial": trial,
                "acss_type": acss_type,
                "deg": deg,
                "wait_time": wait_time,
                "timeout": timeout,
                "regions": REGIONS,
                "instance_type": INSTANCE_TYPE,
                "num_nodes": num_nodes,
                "avg_dealer_stats": ad_stats, 
                "avg_rcv_stats": ar_stats, 
                "outputs": outputs,
                "stats": stats, 
                }
        json_data = json.dumps(data, indent=4)
        f.write(json_data)

if __name__ == "__main__":
    if len(sys.argv) < 7:
        bail(f"{sys.argv[0]} [TRIAL] [REPETITIONS] [TIMEOUT] <ACSS_TYPE> <DEG> <SEED> <WAIT TIME>")

    acss_type, deg, seed, wait_time = None, None, None, None
    if len(sys.argv) == 8:
        acss_type = sys.argv[4]
        deg = sys.argv[5]
        seed = sys.argv[6]
        wait_time = sys.argv[7]
    try:
        repetitions = int(sys.argv[2])
    except ValueError:
            bail(f"REPETITIONS = {sys.argv[2]} is not an integer")
    try:
        timeout = int(sys.argv[3])
    except ValueError:
            bail(f"TIMEOUT = {sys.argv[3]} is not an integer")

    experiment(sys.argv[1], repetitions, timeout, acss_type=acss_type, deg=deg, seed=seed, wait_time=wait_time)
