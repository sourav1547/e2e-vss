# Project config
PROJECT = "acss"
PKG_NAME = "cli-1.0-1.x86_64.rpm"
BINARY_NAME = "cli"
ACSS_PORT = 13021
BENCH_RESULT_DIR="experiments"

# EC2 Config
INSTANCE_TYPE = "t3a.xlarge"
IAM_INSTANCE_PROFILE = {
        "Arn": "arn:aws:iam::324584057370:instance-profile/Ec2BenchmarkRole",
}
OPEN_PORTS = [
        ACSS_PORT
]
# Region: (AMI, VPC)
REGIONS = {
        "us-east-2": ("ami-09e2d756e7d78558d", "vpc-17ecf57f"),
        # "us-east-1": ("ami-05fa00d4c63e32376", "vpc-09750316c0cd0d450"),
        # "us-east-2": ("ami-0568773882d492fc8", "vpc-083a279f83f3aa65b"),
        # "us-west-1": ("ami-018d291ca9ffc002f", "vpc-09983ca9a25ee7160"),
        # "us-west-2": ("ami-0c2ab3b8efb09f272", "vpc-0301fd75a5b74770b"),
        # "ca-central-1": ("ami-06b0bb707079eb96a", "vpc-0572b93cbb72a0a0f"),
        # "ap-northeast-1": ("ami-0f36dcfcc94112ea1", "vpc-0762764d4ebbedf85"),
        # "ap-southeast-1": ("ami-0b89f7b3f054b957e", "vpc-07f97852441242076"),
}
