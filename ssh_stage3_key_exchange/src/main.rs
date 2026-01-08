use clap::{Parser, Subcommand};
use ssh_stage3_key_exchange::server;
use ssh_stage3_key_exchange::client;
use std::process;

#[derive(Parser)]
#[command(name = "ssh_stage3_key_exchange")]
#[command(about = "SSH Phase 3: Key Exchange Implementation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run SSH server
    Server {
        /// Port to listen on
        #[arg(short, long, default_value = "2222")]
        port: u16,
    },
    /// Run SSH client
    Client {
        /// Server hostname
        #[arg(short = 'H', long)]
        host: String,
        /// Server port
        #[arg(short, long, default_value = "2222")]
        port: u16,
        /// Username
        #[arg(short, long)]
        user: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { port } => {
            if let Err(e) = server::run(port) {
                eprintln!("Server error: {}", e);
                process::exit(1);
            }
        }
        Commands::Client { host, port, user } => {
            if let Err(e) = client::connect(&host, port, &user) {
                eprintln!("Client error: {}", e);
                process::exit(1);
            }
        }
    }
}
