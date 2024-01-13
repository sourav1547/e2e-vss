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
        # "ca-central-1": ("ami-06b0bb707079eb96a", "vpc-0572b93cbb72a0a0f"),
        # "ap-northeast-1": ("ami-0f36dcfcc94112ea1", "vpc-0762764d4ebbedf85"),
        # "ap-southeast-1": ("ami-0b89f7b3f054b957e", "vpc-07f97852441242076"),
}
