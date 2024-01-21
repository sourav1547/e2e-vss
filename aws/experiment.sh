# script -a -c "./experiment.py expt-256 10 50 yurek 85 1024 0" results_256.dat
# wait

# script -a -c "./experiment.py expt-256 10 50 groth 85 1024 0" results_256.dat
# wait

# script -a -c "./experiment.py expt-256 10 50 low-ed 85 1024 0" results_256.dat
# wait

# script -a -c "./experiment.py expt-256 10 50 low-bls 85 1024 0" results_256.dat
# wait

# script -a -c "./experiment.py expt-256 10 50 mix-ed 170 1024 0" results_256.dat
# wait

script -a -c "./experiment.py expt-256 10 50 mix-bls 170 1024 0" results_256.dat
wait