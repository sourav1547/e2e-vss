#! /usr/bin/env bash

# Make directories
mkdir -p out
mkdir -p tmp

TMP=$(mktemp -d -p tmp/)

# Rebuild project
cargo build --release &> /dev/null

# Generate configs
touch $TMP/ips
for ((i=0; i<$2; i++))
do
        echo "127.0.0.1:$((30200+$i))" >> $TMP/ips 
done
GEN=$(./target/release/cli generate -d $TMP -f $TMP/ips) 

$1 <<EOT
#! /usr/bin/env bash

#SBATCH --job-name=acss$2_$3
#SBATCH --output=out/acss$2_$3.csv
#SBATCH --time=00:03:00
#SBATCH --nodes=1
#SBATCH --cpus-per-task=$3
#SBATCH --exclusive
#SBATCH --mem=$3G
#SBATCH --no-requeue
#SBATCH --export=NONE
unset SLURM_EXPORT_ENV

# Better debugging
RUST_BACKTRACE=full

function run() {
        local OUTPUT="\$(./target/release/cli run -c ./$TMP/node_\$1.cfg -s partial -a $3 -d $4 -p $5 -w $6)"
        printf "\$OUTPUT\\n";
}


# Run 

for i in \$(seq 0 $(( $2 - 1 )))
do
        run \$i &
done

wait
rm -r $TMP

EOT
