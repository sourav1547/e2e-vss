import boto3
import botocore
from botocore.exceptions import BotoCoreError
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from config import *
from utils import *

class EC2Instance:
    def __init__(self, trial):
        self.trial = trial
        self._instances = None
        self._ssms = None
        self._ec2_resources = None
        self._ec2_clients = None
        self._security_groups = None

    @property
    def ec2_clients(self):
        if self._ec2_clients is None:
            try:
                self._ec2_clients = dict(map(lambda r: (r, boto3.client("ec2", region_name=r)), REGIONS.keys()))
            except BotoCoreError as e:
                bail(f"Creating EC2 clients failed:\n{e}")
        return self._ec2_clients

    @property
    def ec2_resources(self):
        if self._ec2_resources is None:
            try:
                self._ec2_resources = dict(map(lambda r: (r, boto3.resource("ec2", region_name=r)), REGIONS.keys()))
            except BotoCoreError as e:
                bail(f"Creating EC2 resources failed:\n{e}")
        return self._ec2_resources

    @property
    def ssms(self):
        if self._ssms is None:
            try:
                self._ssms = dict(map(lambda r: (r, boto3.client("ssm", region_name=r)), REGIONS.keys()))
            except BotoCoreError as e:
                bail(f"Creating SSMs failed:\n{e}")
        return self._ssms

    def _filter_settings(self):
        return [{"Name": "tag:project", "Values": [PROJECT]}, {"Name": "tag:trial", "Values": [self.trial]}]

    def _tags(self):
        return [{"Key": "project", "Value": PROJECT}, {"Key": "trial", "Value": self.trial}]

    @property
    def instances(self):
        if self._instances is None:
            try:
                self._instances = {}
                for region in REGIONS.keys():
                    self._instances[region] = list(self.ec2_resources[region].instances.filter(
                        Filters = self._filter_settings() + [{"Name": "instance-state-name", "Values": ["running"]}]))
            except BotoCoreError as e:
                bail(f"Getting instances failed:\n{e}")
        return self._instances

    def instances_filtered(self, tag, value):
        instances = {}
        for region in REGIONS.keys():
            instances[region] = list(self.ec2_resources[region].instances.filter(
                Filters=self._filter_settings() +
                        [{"Name": "instance-state-name", "Values": ["running"]}, {"Name": f"tag:{tag}", "Values": [value]}]))
        return instances

    def instance_count(self):
        count = 0
        for instances in self.instances.values():
            count += len(instances)
        return count

    @property
    def security_groups(self):
        if self._security_groups is None:
            try:
                self._security_groups = {}
                for region in REGIONS.keys():
                    sgs = list(self.ec2_resources[region].security_groups.filter(Filters = self._filter_settings()))
                    assert not sgs or len(sgs) == 1, "Got multiple security groups!"
                    if sgs:
                        self._security_groups[region] = sgs[0]
                    else:
                        self._security_groups[region] = self.create_security_group(region)
            except BotoCoreError as e:
                bail(f"Getting security groups failed:\n{e}")
        return self._security_groups

    def create_security_group(self, region):
        try:
            sg = self.ec2_resources[region].create_security_group(
                    GroupName=f"SG_{PROJECT}_{self.trial}_{region}",
                    Description=f"Security group for project {PROJECT} during trial {self.trial} in region {region}.",
                    VpcId=REGIONS[region][1],
                    TagSpecifications=[{ "ResourceType": "security-group", "Tags": self._tags() }])
        except BotoCoreError as e:
            bail(f"Creating security group in region {region} failed:\n{e}")

        if OPEN_PORTS:
            try:
                sg.authorize_ingress(
                        IpPermissions = list(map(lambda port: {
                            "IpProtocol": "tcp",
                            "FromPort": port,
                            "ToPort": port,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                            OPEN_PORTS)))
            except BotoCoreError as e:
                bail(f"Opening ports in security group {sg.id} failed:\n{e}")
        return sg

    def spawn_instances(self, count, setup_command=""):
        region_count, remainder = divmod(count, len(REGIONS))
        assert remainder == 0, "Remainder is not 0!"
        instances = {}
        for (region, (ami, _)) in REGIONS.items():
            print(f"Launching {region_count} instances in {region}...")
            try:
                region_instances = self.ec2_resources[region].create_instances(
                        ImageId=ami,
                        MinCount=region_count,
                        MaxCount=region_count,
                        SecurityGroupIds=[self.security_groups[region].id],
                        InstanceType=INSTANCE_TYPE,
                        IamInstanceProfile=IAM_INSTANCE_PROFILE,
                        TagSpecifications=[{ "ResourceType": "instance", "Tags": self._tags() }],
                        UserData=setup_command)
                instances[region] = region_instances
            except BotoCoreError as e:
                bail(f"Creating instance in region {region} failed:\n{e}")
            except botocore.exceptions.ClientError as e:
                bail(f"Creating instance in region {region} failed:\n{e}")

        # Wait for instances
        for region in REGIONS.keys():
            if region in instances:
                try:
                    waiter = self.ec2_clients[region].get_waiter("instance_running")
                    waiter.wait(InstanceIds=map_to_id(instances[region]))
                except BotoCoreError as e:
                    bail(f"Waiting for instances in region {region} failed:\n{e}")
                self.instances[region] += instances[region] 

    def terminate(self, wait=True):
        print("Terminating EC2 instances...")
        for region in REGIONS.keys():
            if region in self.instances and self.instances[region]:
                try:
                    self.ec2_clients[region].terminate_instances(InstanceIds=map_to_id(self.instances[region]))
                except BotoCoreError as e:
                    eprint(f"Terminating instance in region {region} failed:\n{e}")

        if wait:
            for region in REGIONS.keys():
                if region in self.instances and self.instances[region]:
                    try:
                        waiter = self.ec2_clients[region].get_waiter("instance_terminated")
                        waiter.wait(InstanceIds=map_to_id(self.instances[region]))
                    except BotoCoreError as e:
                        eprint(f"Termination waiter in {region} failed:\n{e}")

        self._instances = None

    def delete_security_groups(self):
        for region in REGIONS.keys():
            if region in self.security_groups and self.security_groups[region]:
                try:
                    self.security_groups[region].delete()
                except BotoCoreError as e:
                    eprint(f"Termination of security group in {region} failed:\n{e}")
        self._security_groups = None

    def run_commands(self, commands, instances=None, max_wait_sec=60, wait_sec=10, output=False):
        if max_wait_sec < wait_sec:
            wait_sec = max_wait_sec

        command_ids = {}


        instances_to_use = instances if instances else self.instances
        def send(x):
            return (x[0], x[1].send_command(
                Targets=[{
                    "Key": "InstanceIds",
                    "Values": map_to_id(instances_to_use[x[0]])}],
                MaxConcurrency="100%",  # So that all nodes can execute it simultaneously
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands, "workingDirectory": ["/home/ec2-user"], "executionTimeout": [str(max_wait_sec)]}))

        with ThreadPoolExecutor(max_workers=8) as exe:
            try:
                res = exe.map(send, self.ssms.items())
            except BotoCoreError as e:
                bail(f"Running commands {commands} in failed:\n{e}")

            for (region, cmd) in res:
                command_ids[region] = cmd["Command"]["CommandId"]
            
        completed_regions = set()
        while len(completed_regions) < len(command_ids):
            time.sleep(wait_sec)
            for (region, ssm) in self.ssms.items():
                if region not in command_ids or region in completed_regions:
                    continue
                try:
                    cmd_status = ssm.list_commands(CommandId=command_ids[region])["Commands"][0]["Status"]
                    if cmd_status != "Pending" and cmd_status != "InProgress":
                        completed_regions.add(region)
                    
                except BotoCoreError as e:
                    bail(f"Running commands {commands} in {region} failed:\n{e}")

            # if len(completed_regions) < len(command_ids) and max_wait_sec <= wait_sec * retries:
            #     eprint("Command timed out in some regions! Cancelling...")
            #     for (region, ssm) in self.ssms.items():
            #         if region not in command_ids or region in completed_regions:
            #             continue
            #         try:
            #             ssm.cancel_command(CommandId=command_ids[region])
            #         except BotoCoreError as e:
            #             eprint(f"Cancelling commands {commands} in {region} failed:\n{e}")
            #     return

        if output:
            outputs = []
            for (region, ssm) in self.ssms.items():
                if region not in command_ids:
                    continue
                for instance in instances_to_use[region]:
                    try:
                        invocation = ssm.get_command_invocation(
                                CommandId=command_ids[region],
                                InstanceId=instance.id)
                        if invocation["Status"] == "Success":
                            outputs.append(invocation["StandardOutputContent"].rstrip("\n"))
                        else:
                            outputs.append(invocation["Status"])
                    except BotoCoreError as e:
                        bail(f"Getting command output in {region} failed:\n{e}")
            return outputs
        else:
            return None

    def get_ips(self):
        ips = {}
        for instances in self.instances.values():
            for instance in instances: 
                try:
                    ips[instance.id] = instance.public_ip_address
                except BotoCoreError as e:
                    bail(f"Getting ip for instance {instance.id} failed:\n{e}")
        return ips

    def tag(self, instances, tag, value):
        for (region, instances) in instances.items():
            try:
                self.ec2_resources[region].create_tags(
                    Resources=map_to_id(instances),
                    Tags=[{"Key": tag, "Value": value}])
            except BotoCoreError as e:
                bail(f"Setting tag {tag}:{value} in {region} failed:\n{e}")

class S3Bucket:
    def __init__(self, trial, region=None):
        self.name = f"spiders-{PROJECT}-{trial}".replace("_", "-")
        self.region = region if region else "eu-west-1"
        self._resource = None
        self._bucket = None

    @property
    def resource(self):
        if self._resource is None:
            try:
                self._resource = boto3.resource("s3", region_name=self.region)
            except BotoCoreError as e:
                bail(f"Creating S3 resource failed:\n{e}")
        return self._resource

    @property
    def bucket(self):
        if self._bucket is None:
            try:
                bucket = [b for b in self.resource.buckets.all() if b.name == self.name]
            except BotoCoreError as e:
                bail(f"Listing buckets failed:\n{e}")
            self._bucket = bucket[0] if bucket else None
        return self._bucket

    def create(self):
        assert not self.bucket, "Bucket is not None!"
        try:
            self._bucket = self.resource.create_bucket(
                Bucket=self.name,
                ACL="private",
                CreateBucketConfiguration={"LocationConstraint": self.region})
        except BotoCoreError as e:
            bail(f"Creating bucket failed:\n{e}")

    def delete(self):
        if self.bucket:
            try:
                self.bucket.objects.delete()
                self.bucket.delete()
            except BotoCoreError as e:
                eprint(f"Deleting Bucket failed:\n{e}")

    def upload_file(self, local_path, remote_path):
        if not self.bucket:
            self.create()
        try:
            self.bucket.upload_file(local_path, remote_path)
        except BotoCoreError as e:
            bail(f"Upload failed:\n{e}")
