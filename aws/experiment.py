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

        ad_stats = {"latency": [], "bandwidth": [], "msg_count":[]}
        ar_stats = {"latency": [], "bandwidth": [], "msg_count":[]}

        for i in range(0, repetitions):
            print(f"Experiment {i}...")
            cmd = "cli run -c node.cfg -s full"
            if partial_stats:
                cmd = "cli run -c node.cfg -s partial -t 128 -r 128"
            if acss_type:
                cmd += f" -a '{acss_type}' -d '{deg}' -p '{int(seed)+i}' -w '{wait_time}'"
            print(cmd)
            outputs[i] = ec2.run_commands([cmd], max_wait_sec=timeout, output=True) 

            if partial_stats:
                dealer_latency = 0
                dealer_sent = 0
                dealer_count = 0
                timeout_count = 0

                rcv_stats = {"latency":[], "msg_count":[], "bandwidth":[]}
                for value in outputs[i]:
                    if value == "TimedOut" or value=="Failed":
                        timeout_count += 1
                        continue
                    if len(value.split("\n")) < 2:
                        print(value)
                        continue
                    v1, v2 = value.split("\n")
                    v1_data = list(map(int, v1.split(",")))
                    v2_data = list(map(int, v2.split(",")))
                    
                    sent = v1_data
                    rcvd = v2_data
                    if len(sent) == 2:
                        sent = v2_data
                        rcvd = v1_data
                    
                    idx, byte_sent, sent_count, latency = sent[0], sent[1], sent[2], sent[3]
                    rcvd_count, byte_rcvd = rcvd[0], rcvd[1]

                    if idx == 0:
                        dealer_lt = latency
                        dealer_bw = (byte_sent + byte_rcvd)/2**10
                        dealer_mc = sent_count + rcvd_count
                    
                    if idx != 0:
                        rcv_stats["latency"].append(latency)
                        rcv_stats["msg_count"].append(sent_count + rcvd_count )
                        rcv_stats["bandwidth"].append(byte_sent + byte_rcvd)
                
                rcv_avg_lt = mean(rcv_stats["latency"])
                rcv_avg_mc = mean(rcv_stats["msg_count"])
                rcv_avg_bw = mean(rcv_stats["bandwidth"])/2**10

                dealer_mc -= rcv_avg_mc
                dealer_bw -= rcv_avg_bw

                print("")
                print(f"{'Latency:':<25}{round(dealer_lt, 2):<20}")
                print(f"{'Dealer BW (KBytes):':<25}{round(dealer_bw, 2):<20}{'Dealer Msg Count:':<20}{round(dealer_mc, 2)}")
                
                # print(f"{'Rcv Latency:':<15}{round(rcv_avg_latency, 2):<20}{'Rcv BW (KBytes):':<25}{round(rcv_avg_byte_sent, 2):<20}{'Rcv Msg Count:':<20}{round(rcv_avg_msg_count, 2)}")
                print(f"{'Rcv BW (KBytes):':<25}{round(rcv_avg_bw, 2):<20}{'Rcv Msg Count:':<20}{round(rcv_avg_mc, 2)}")

                print(f"Number of timeouts: {timeout_count}")

                print("-"*50)

                dealer_stats = {
                    "Latency": round(dealer_lt, 2),
                    "Dealer BW (KBytes)": round(dealer_bw, 2),
                    "Dealer Msg Count": round(dealer_mc, 2)
                }

                non_dealer_stats = {
                    # "Rcv Latency": round(rcv_avg_latency, 2),
                    "Rcv BW (KBytes)": round(rcv_avg_bw, 2),
                    "Rcv Msg Count": round(rcv_avg_mc, 2)
                }

                stats[i] = {"dealer_stats": dealer_stats, "non_dealer_stats": non_dealer_stats}

                ad_stats["latency"].append(dealer_lt)
                ad_stats["bandwidth"].append(dealer_bw)
                ad_stats["msg_count"].append(dealer_mc)

                # ar_stats["latency"].append(rcv_avg_latency)
                ar_stats["bandwidth"].append(rcv_avg_bw)
                ar_stats["msg_count"].append(rcv_avg_mc)
    
        print("------------- Avergage of Average -------------")

        ad_lt = round(mean(ad_stats["latency"]), 2)
        ad_bw = round(mean(ad_stats["bandwidth"]), 2)
        ad_mc = round(mean(ad_stats["msg_count"]),2)

        # ar_latency = round(mean(ar_stats["latency"]),2)
        ar_bw = round(mean(ar_stats["bandwidth"]),2)
        ar_mc = round(mean(ar_stats["msg_count"]),2)


        ad_stats = {
            "Latency": ad_lt,
            "Dealer BW (KBytes)": ad_bw,
            "Dealer Msg Count": ad_mc
        }

        ar_stats = {
            # "Rcv Latency": ar_lt,
            "Rcv BW (KBytes)": ar_bw,
            "Rcv Msg Count": ar_mc
        }

        print(f"{'Latency:':<25}{ad_lt:<20}")
        print(f"{'Dealer BW (KBytes):':<25}{ad_bw:<20}{'Dealer Msg Count:':<20}{ad_mc}")
        print(f"{'Rcv BW (KBytes):':<25}{ar_bw:<20}{'Rcv Msg Count:':<20}{ar_mc}")
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
