use std::sync::mpsc::Receiver;
use std::time::Duration;
use std::{fs, io, thread};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use acss::rbc::RBCParams;
use acss::vss::groth_ni_acss::{GrothReceiverParams, GrothReceiver, GrothSenderParams, GrothSender};
use acss::vss::low_bls_acss::{LowBLSReceiverParams, LowBLSReceiver, LowBLSSenderParams, LowBLSSender};
use acss::vss::low_ed_acss::{LowEdSenderParams, LowEdSender, LowEdReceiverParams, LowEdReceiver};
use acss::vss::messages::ACSSDeliver;
use acss::vss::mixed_bls_acss::{MixedBLSReceiverParams, MixedBLSReceiver, MixedBLSSender, MixedBLSSenderParams};
use acss::vss::mixed_ed_acss::{MixedEdReceiverParams, MixedEdReceiver, MixedEdSenderParams, MixedEdSender};
use acss::vss::yurek_acss::{YurekReceiver, YurekReceiverParams, YurekSenderParams, YurekSender};
use rand::thread_rng;

use acss::DST_PVSS_PUBLIC_PARAMS_GENERATION;
use acss::pvss::SharingConfiguration;
use acss::vss::keys::InputSecret;
use anyhow::{anyhow, ensure, Result};
use group::Group;
use tokio;
use clap::{Parser, Subcommand};
use blstrs::G1Projective;
use serde::{Deserialize, Serialize};
use network::message::Id;
use protocol::{Node, Protocol, ProtocolParams, run_protocol};
use utils::{yurek_params, low_ed_params, low_bls_params, mixed_ed_params, mixed_bls_params, groth_params};

pub mod utils;

// use acss::vss::simple_acss::ACSSParams;

#[derive(Parser)]
#[clap(version)]
struct Cli {
    /// Enables debug output. Multiple occurrences increase its verbosity
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
    #[clap(subcommand)]
    command: Commands
}

enum Stats {
    Off,
    Partial,
    Full,
}

impl Stats {
    fn should_collect(&self) -> bool {
        match self {
            Stats::Off => false,
            _ => true,
        }
    }
}

impl FromStr for Stats {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "partial" => Ok(Self::Partial),
            "full" => Ok(Self::Full),
            x => Err(anyhow!("{} can't be turned into Stats!", x))
        }
    }
}

enum ACSSType {
    Yurek, 
    LowEd, 
    LowBLS,
    MixEd,
    MixBLS,
    Groth,
}

impl FromStr for ACSSType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "yurek" => Ok(Self::Yurek),
            "low-ed" => Ok(Self::LowEd),
            "low-bls" => Ok(Self::LowBLS),
            "mix-ed" => Ok(Self::MixEd),
            "mix-bls" => Ok(Self::MixBLS),
            "groth" => Ok(Self::Groth),
            x => Err(anyhow!("{} can't be turned into ACSSType!", x))
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Generates an initial setup for all nodes given a list of socket addresses.
    Generate {
        /// Directory where the config files will be stored.
        #[clap(short, long, parse(from_os_str), value_name = "DIR")]
        dir: PathBuf,
        /// File to read the socket addresses from; one address per line. If not given, uses STDIN.
        #[clap(short, long, parse(from_os_str), value_name = "FILE")]
        file: Option<PathBuf>,

        /// Whether to name the files using IPs
        #[clap(short, long)]
        ips: bool
    },
    /// Runs a node given an initial config and a list of peers.
    Run {
        /// Config file.
        #[clap(short, long, parse(from_os_str), value_name = "FILE")]
        config: PathBuf,

        #[clap(short, long, value_name = "TOKIO_THREADS")]
        tokio_threads: Option<usize>,

        #[clap(short, long, value_name = "RAYON_THREADS")]
        rayon_threads: Option<usize>,

        #[clap(short, long)]
        stats: Stats,
        
        #[clap(short, long)]
        acss_type: ACSSType,

        #[clap(short, long)]
        deg: usize,

        #[clap(short, long)]
        prg: usize, // Pseudorandom seed for generating keys
        
        #[clap(short, long)]
        wait: usize, // Wait time before broadcasting the RBC message
    }
}


fn read_to_string(path: &Option<PathBuf>) -> Result<String> {
    // Bit dirty but it's only for configs so doesn't really matter
    Ok(match path {
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        },
        Some(f) => fs::read_to_string(f)?
    })
}

#[derive(Serialize, Deserialize)]
struct NodeWithGens {
    pub node: Node<RBCParams>,
    pub g: G1Projective,
    pub h: G1Projective,
}


fn main() -> Result<()> {
    simple_logger::init_with_level(log::Level::Warn).expect("Initializing logger failed!");
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { mut dir, file, ips} => {
            ensure!(dir.is_dir(), "dir is not a directory!");

            let contents = read_to_string(&file)?;
            let mut node_addrs: Vec<_> = contents.lines().map(|x| SocketAddr::from_str(x.trim())).collect::<Result<Vec<_>, _>>()?;
            let n = node_addrs.len();
            let th = n/3;
            assert!(n>=3*th+1);
            
            // deduplicate addresses
            node_addrs.sort();
            node_addrs.dedup();
            ensure!(node_addrs.len() == n, "Contains at least one duplicate socket address!");

            let seed = b"hello";
            let g = G1Projective::generator(); 
            let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
            let params = RBCParams::new(n, th);
            let configs: Vec<_>= Node::<RBCParams>::
            generate_nodes(node_addrs, th, params)?;

            for (i, cfg) in configs.into_iter().enumerate() {
                if ips {
                    dir.push(format!("{}.cfg", cfg.get_own_socket_addr().ip()));
                } else {
                    dir.push(format!("node_{}.cfg", i));
                }
                let file = File::create(&dir)?;
                let node_gen = NodeWithGens { node: cfg, g, h };
                bincode::serialize_into(&file, &node_gen)?;
                dir.pop();
            }
            Ok(())
        }
        Commands::Run { config, tokio_threads, rayon_threads, stats, acss_type, deg, prg, wait } => {
            let err_string = format!("Can't open config file! {:#?}", config);
            let mut reader = File::open(config).expect(&err_string);
            let NodeWithGens{node, g, h} = bincode::deserialize_from(&mut reader).expect("Can't deserialize config!");
            let mut rt = tokio::runtime::Builder::new_multi_thread();

            if let Some(num_threads) = rayon_threads {
                rayon::ThreadPoolBuilder::new().num_threads(num_threads).build_global().unwrap();
            }

            if let Some(num_threads) = tokio_threads {
                rt.worker_threads(num_threads);
            }
            rt.enable_all().build().unwrap().block_on(async move {
                let mut handle = node.spawn_manager(stats.should_collect());

                let n = node.get_num_nodes();
                let sender = 0;

                let sc = SharingConfiguration::new(deg+1, n);
                let s = {
                    let mut rng = thread_rng();
                    InputSecret::new_random(&sc, true, &mut rng)
                };
                let bases = [g,h];

                let id = Id::default();
                let dst = "DST".to_string();
                let start_delay = Duration::from_millis(2000);
                let self_idx = node.get_own_idx();
                let mut rx;
                
                // Start timer
                handle.handle_stats_start("Node");
                match acss_type {
                    ACSSType::Yurek => {
                        let ekeys = yurek_params(n, bases);
                        (_, rx) = {
                            let recv_params = YurekReceiverParams::new(sender, ekeys.clone(), sc.clone(), bases);
                            run_protocol!(YurekReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), "DST".to_string(), recv_params)
                        };

                        thread::sleep(start_delay);

                        if sender == self_idx {
                            let params = YurekSenderParams::new(sc, s, bases, ekeys);
                            let _ = run_protocol!(YurekSender, handle.clone(), Arc::new(node), id, dst, params);
                        }
                    },

                    ACSSType::LowEd => {
                        let (sk, vkeys) = low_ed_params(&sc, self_idx);
                        (_, rx) = {
                            let recv_params = LowEdReceiverParams::new(bases, vkeys.clone(), sk, sender, sc.clone());
                            run_protocol!(LowEdReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), dst.clone(), recv_params)
                        };

                        thread::sleep(start_delay);
                        if sender == self_idx {
                            let params = LowEdSenderParams::new(bases, vkeys, sc, s);
                            let _ = run_protocol!(LowEdSender, handle.clone(), Arc::new(node), id, dst, params);
                        }
                    },
                    ACSSType::LowBLS => {
                        let (sk, vks) = low_bls_params(&sc, self_idx);
                        (_, rx) = {
                            let recv_params = LowBLSReceiverParams::new(bases, vks.clone(), sk, sender, sc.clone());
                            run_protocol!(LowBLSReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), dst.clone(), recv_params)
                        };

                        thread::sleep(start_delay);

                        if sender == self_idx {
                            let params = LowBLSSenderParams::new(bases, vks, sc, s);
                            let _ = run_protocol!(LowBLSSender, handle.clone(), Arc::new(node), id, dst, params);
                        }
                    },
                    ACSSType::MixEd => {
                        let (sk, vkeys ,ekeys) = mixed_ed_params(&sc, &bases, self_idx);

                        (_, rx) = {
                            let recv_params = MixedEdReceiverParams::new(bases, vkeys.clone(), ekeys.clone(), sk, sender, sc.clone());
                            run_protocol!(MixedEdReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), dst.clone(), recv_params)
                        };

                        thread::sleep(start_delay);

                        if sender == self_idx {
                            let params = MixedEdSenderParams::new(bases, vkeys, ekeys, sc, s, wait);
                            let _ = run_protocol!(MixedEdSender, handle.clone(), Arc::new(node), id, dst, params);
                        }
                    },
                    ACSSType::MixBLS => {
                        let (sk, vkeys,ekeys) = mixed_bls_params(&sc, &bases, self_idx);

                        (_, rx) = {
                            let recv_params = MixedBLSReceiverParams::new(bases, vkeys.clone(), ekeys.clone(), sk, sender, sc.clone());
                            run_protocol!(MixedBLSReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), dst.clone(), recv_params)
                        };

                        thread::sleep(start_delay);

                        if sender == self_idx {
                            let params = MixedBLSSenderParams::new(bases, vkeys, ekeys, sc, s, wait);
                            let _ = run_protocol!(MixedBLSSender, handle.clone(), Arc::new(node), id, dst, params);
                        }
                    },
                    ACSSType::Groth => {
                        let (dk, ekeys) = groth_params(&sc, &bases, self_idx);

                        (_, rx) = {
                            let add_params = GrothReceiverParams::new(bases, ekeys.clone(), sender, dk, sc.clone());
                            run_protocol!(GrothReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), dst.clone(), add_params)
                        };

                        thread::sleep(start_delay);

                        if sender == self_idx {
                            let params = GrothSenderParams::new(sc, s, bases, ekeys);
                            let _ = run_protocol!(GrothSender, handle.clone(), Arc::new(node), id, dst, params);
                        }
                    },
                };

                let ACSSDeliver{..} = rx.recv().await.unwrap();  
                // End timer
                handle.handle_stats_end().await;

                // Waiting for sometime before shutting down, so others can finish.
                thread::sleep(start_delay);

                // Stats
                let manager_stats = handle.sender_stats().await;
                // Shutdown handle gracefully
                handle.shutdown().await;

                if let Some(manager_stats) = manager_stats {
                    match stats {
                        Stats::Full => {
                            let serialized = serde_json::to_string(&manager_stats)?;
                            println!("{}", serialized);
                        }
                        Stats::Partial => {
                            for handle_stat in manager_stats.handle_stats().iter() {
                                let label = handle_stat.get_label();
                                if label.is_some() && label.as_ref().unwrap() == "Node" {
                                    // csv node_id,sent_bytes,sent_count,duration
                                    println!("{},{},{},{}", self_idx,
                                             manager_stats.sent_bytes(),
                                             manager_stats.sent_count(),
                                             handle_stat.duration().expect("No duration!"));
                                }
                            }
                        }
                        Stats::Off => {}
                    }
                }
                Ok(())
            })
        }
    }
}
