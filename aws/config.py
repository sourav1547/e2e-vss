# Project config
PROJECT = "acss"
PKG_NAME = "cli-1.0-1.x86_64.rpm"
BINARY_NAME = "cli"
ACSS_PORT = 13021
BENCH_RESULT_DIR="experiments"

# EC2 Config
INSTANCE_TYPE = "c5.2xlarge"
IAM_INSTANCE_PROFILE = {
        "Arn": "arn:aws:iam::395431295218:instance-profile/vss",
}
OPEN_PORTS = [
        ACSS_PORT
]
# Region: (AMI, VPC)
REGIONS = {
        "us-east-2": ("ami-0cd3c7f72edd5b06d", "vpc-17ecf57f"),
        "us-east-1": ("ami-0005e0cfe09cc9050", "vpc-850798ff"),
        "us-west-1": ("ami-0a5ed7a812aeb495a", "vpc-ca615aad"),
        "us-west-2": ("ami-0944e91aed79c721c", "vpc-b6c46cce"),
        "ca-central-1": ("ami-0b7fec1e45e0e5ae5", "vpc-dff79eb7"),
        "eu-west-1": ("ami-062a49a8152e4c031", "vpc-43d9dc25"),
        "ap-northeast-1": ("ami-0506f0f56e3a057a4", "vpc-07a28d60"),
        "ap-southeast-1": ("ami-0120e0e7231daa18b", "vpc-b31c2ed4"),
}
