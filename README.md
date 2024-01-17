# ACSS
End-to-end implementation of various asynchronous verifiable secret sharing scheme. This code base implements:
1. ACSS scheme of Yurek et al. `yurek_acss.rs`
2. Our low-threshold ACSS using Ed25519 signature scheme. `low_ed_acss.rs`
3. Our low-threshold ACSS with BLS multisignature `low_bls_acss.rs`
4. Our dual-threhsold ACSS with Ed25519 signature scheme. `mixed_ed_acss.rs`
5. Our dual-threhsold ACSS with BLS multisignature scheme. `mixed_bls_acss.rs`
6. ACSS scheme of Groth `groth_ni_acss.rs`


## Running
### Running on a local machine
The project is fully written in Rust and should compile using `cargo` on any reasonable machine. 

After building, you can execute the `cli` binary. Alternatively, it might be easier to use `cargo run`. There are two steps needed to run the protocol locally.
1. Generate a config using `cli generate`. You need to provide a file where each line contains a pair `<IP>:<PORT>`.
2. Run each node using `cli run`. You need to pass a config file (generated in the previous step) to each node.
For further information, please check `cli --help` (or `cargo run -- --help`). This also works for subcommands, e.g., `cli generate --help`.


As a convenience, you can also use `run.sh`. It automates the config generation and node execution. To run a test across `NUM_NODES` nodes use `./run.sh bash [NUM_NODES] [ACSS_TYPE] [DEG] [SEED] [WAIT_TIME]`. For example, if you run `./run.sh bash 16 low-ed 10 1024 10`, it wiill run our low-threshold ACSS scheme with 16 nodes, use a polynomial degree of `10`, and use 1024 as the seed for generating random numbers. 

PARAMETER CHOICES:
1. Choice of `ACSS_TYPE` are: `yurek`, `low-ed`, `low-bls`, `mix-ed`, `mix-bls`, and `groth`.
2. For all our schemes, i.e., `low-X` and `mix-X`, for now we only support `t=n/3` and `deg=2*t`.


Finally, to kill any running instances, use `pkill -f "./target/release/cli"`.


### Running on AWS 
`aws/` contains Python scripts to deploy and benchmark the system on AWS. Check out the README in the directory for more details.

### Microbenchmarking computation costs
To microbenchmark the the computation costs, change directory to `benches` using `cd benches/`, and run  `cargo bench [EXPT]`. Here, choices of `EXPT` are `yurek`, `low-ed`, `low-bls`, `mix-ed`, `mix-bls`, `groth`, and `common`. Each `EXPT` with an acss type, measures the dealing-time and verification time. The `common` benchmarks the cost of reconstruction, and low-degree test.

## Structure
In more detail, the code is split across the following crates:
* `acss` is where most of our code lies.
* `utils` offers some useful macros (primarily for dealing with `tokio` channels).
* `network` handles asynchronous network conditions, e.g., retrying after transmission failures, caching messages which are not yet required. It offers a pub-sub-style interface for sub-protocols.
* `protocol` offers common traits that describe protocols.
* `crypto` offers some cryptography traits.
* `cli` is a CLI interface for APSS. After building, run `cli --help` to learn more.
* `benches` code for micro-benchmarking computation costs.

## Acknowledgement
We use the networking component from this https://github.com/ISTA-SPiDerS/apss repository.