use std::{fs, io};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use acss::rbc::RBCParams;
use acss::vss::messages::ACSSDeliver;
use rand::thread_rng;

use acss::DST_PVSS_PUBLIC_PARAMS_GENERATION;
use acss::pvss::SharingConfiguration;
use acss::vss::keys::InputSecret;
use acss::vss::simple_acss::{ACSSSenderParams, ACSSSender, ACSSReceiverParams, ACSSReceiver};
use anyhow::{anyhow, ensure, Result};
use group::Group;
use tokio;
use clap::{Parser, Subcommand};
use blstrs::G1Projective;
use serde::{Deserialize, Serialize};
use network::message::Id;
use protocol::{Node, Protocol, ProtocolParams, run_protocol};

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
        // /// Reconstruction threshold of the secret.
        // #[clap(short, long)]
        // threshold: usize,
    },
    /// Runs a node given an initial config and a list of peers.
    Run {
        /// Config file.
        #[clap(short, long, parse(from_os_str), value_name = "FILE")]
        config: PathBuf,

        /// Committee probability
        #[clap(short, long, parse(from_str), value_name = "PROB")]
        probability: Option<String>,

        #[clap(short, long, value_name = "TOKIO_THREADS")]
        tokio_threads: Option<usize>,

        #[clap(short, long, value_name = "RAYON_THREADS")]
        rayon_threads: Option<usize>,

        #[clap(short, long)]
        stats: Stats,
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
            let f = n/3;
            
            // deduplicate addresses
            node_addrs.sort();
            node_addrs.dedup();
            ensure!(node_addrs.len() == n, "Contains at least one duplicate socket address!");

            let mut rng = thread_rng();
            let seed = b"hello";
            let g = G1Projective::generator(); 
            let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
            let params = RBCParams::new(n, n/2);
            let configs: Vec<_>= Node::<RBCParams>::
            generate_nodes(node_addrs, f+1, params)?;

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
        Commands::Run { config, probability, tokio_threads, rayon_threads, stats } => {
            let err_string = format!("Can't open config file! {:#?}", config);
            let mut reader = File::open(config).expect(&err_string);
            let NodeWithGens{mut node, g, h} = bincode::deserialize_from(&mut reader).expect("Can't deserialize config!");
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
                let th = node.get_threshold();
                let sender = 0;

                let id = Id::new(0, vec![0]);
                let sc = SharingConfiguration::new(th, n);
                let bases = [g,h];

                if node.get_own_idx() == sender {
                    let mut rng = thread_rng();
                    let s = InputSecret::new_random(&sc, true, &mut rng);
                    let add_params = ACSSSenderParams::new(sc.clone(), s, bases);    
                    let _ = run_protocol!(ACSSSender, handle.clone(), Arc::new(node.clone()), id.clone(), "DST".to_string(), add_params);
                }

                // Start timer
                handle.handle_stats_start("Node");
                let recv_add_params = ACSSReceiverParams::new(sender, sc, bases);
                let (_, mut rx) = run_protocol!(ACSSReceiver, handle.clone(), Arc::new(node.clone()), id.clone(), "DST".to_string(), recv_add_params);
                let ACSSDeliver{..} = rx.recv().await.unwrap();

                // TODO:
                // [] To close the running channels
                
                // End timer
                handle.handle_stats_end().await;

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
                                    println!("{},{},{},{}", node.get_own_idx(),
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
