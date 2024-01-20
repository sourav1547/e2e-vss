NOTE: I have only test this on a Ubuntu 22.04.3 LTS machine

# Deploy to AWS
1. Set credentials in the environment, i.e., set the environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` with appropriate values. You can also use `setup_env.fish` to do that.
2. Set the regions, instance type, etc. in `config.py`.
3. Run `./spawn.py [TRIAL] [NODE_COUNT] <SETUP_COMMAND>` to spawn nodes and one S3 bucket. The trial is a name that you can give the current experiment run and is used in the following commands.
4. Run `./deploy_binary.py [TRIAL]` to build the binary locally and deploy it to the machines.
5. Run `./distribute_config.py [TRIAL]` to generate a config and distribute it.
6. Start experiment(s) with `./experimnt.py [TRIAL] [REPETITIONS] [TIMEOUT] <ACSS_TYPE> <DEG> <SEED> <WAIT_TIME>`. Timeout is in seconds. For example, you can run `./experiment.py rcv 2 20 yurek 4 1024 20` to run 
7. Run `./teardown.py [TRIAL]` to terminate the bucket and all VM instances. 

## Example execution
Here is an example of how to run a 8 node experiment on AWS. Here, we are assuming, you have done the step 1 and 2 of the instructsions mentioned above correctly. The commands to run in steps 3 to 7 are as follows:
3. `./spawn.py test 8`
4. `./deploy_binary.py test`
5. `./distribute_config.py test`
6. `./experiment.py rcv 2 20 yurek 2 1024 20`
7. `./teardown.py test`

# Notes
* You need `nix` to build the binary.
* The instance must have some reasonably recent processors that support certain instruction sets (I believe AVX2).
* You can add nodes to the network by running steps 3-5 again.

### Helper commands for AWS experiments
* Here the environment variable `vss_main` stores the instance id of the `vss-main`
* To start the vss_main instance: `aws ec2 start-instances --instance-ids $vss_main`
* To get the public ip: `aws ec2 describe-instances --instance-ids $vss_main --query 'Reservations[*].Instances[*].PublicIpAddress'`
* To stop the vss_main instance: `aws ec2 stop-instances --instance-ids $vss_main`