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
        "us-east-2": ("ami-0c2f3d2ee24929520", "vpc-17ecf57f"),
        "us-east-1": ("ami-0c0b74d29acd0cd97", "vpc-850798ff"),
        "us-west-1": ("ami-0f30a20675de7eb6e", "vpc-ca615aad"),
        "us-west-2": ("ami-00112c992a47ba871", "vpc-b6c46cce"),
        "ca-central-1": ("ami-0b8f000719123a451", "vpc-dff79eb7"),
        "eu-west-1": ("ami-02a66cf05465c373f", "vpc-43d9dc25"),
        "ap-northeast-1": ("ami-027a31eff54f1fe4c", "vpc-07a28d60"),
        "ap-southeast-1": ("ami-05f23df0095de71bb", "vpc-b31c2ed4"),
}
