use clap::{Parser, Subcommand};
use ssh_stage4_server_authentication::server;
use ssh_stage4_server_authentication::client;
use std::process;

#[derive(Parser)]
#[command(name = "ssh_stage4_server_authentication")]
#[command(about = "SSH Phase 4: Server Authentication Implementation")]
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
        /// Password (optional, will prompt if not provided)
        #[arg(short = 'P', long)]
        password: Option<String>,
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
        Commands::Client { host, port, user, password } => {
            if let Err(e) = client::connect(&host, port, &user, password.as_deref()) {
                eprintln!("Client error: {}", e);
                process::exit(1);
            }
        }
    }
}

