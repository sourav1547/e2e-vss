set -gx AWS_ACCESS_KEY_ID (string split -f 1 : $argv[1])
set -gx AWS_SECRET_ACCESS_KEY (string split -f 2 : $argv[1])
