use clap::{Parser, Subcommand};
use ssh_stage5_client_authentication::server;
use ssh_stage5_client_authentication::client;
use ssh_stage5_client_authentication::keys::SshKeyPair;
use std::process;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ssh_stage5_client_authentication")]
#[command(about = "SSH Phase 5: Client Authentication (Public Key) Implementation")]
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
        /// Password (optional)
        #[arg(short = 'P', long)]
        password: Option<String>,
        /// Private key file for public key authentication
        #[arg(short = 'i', long)]
        identity_file: Option<PathBuf>,
    },
    /// Generate SSH key pair
    Keygen {
        /// Output path for private key (default: id_rsa)
        #[arg(short, long, default_value = "id_rsa")]
        private_key: PathBuf,
        /// Output path for public key (default: id_rsa.pub)
        #[arg(short, long)]
        public_key: Option<PathBuf>,
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
        Commands::Client { host, port, user, password, identity_file } => {
            let key_pair = if let Some(ref _key_path) = identity_file {
                // In a real implementation, we would load the key from file
                // For now, we'll generate a temporary key for demonstration
                println!("Note: Loading keys from file not fully implemented, using generated key");
                Some(SshKeyPair::generate().expect("Failed to generate key"))
            } else {
                None
            };
            
            if let Err(e) = client::connect(&host, port, &user, password.as_deref(), key_pair.as_ref()) {
                eprintln!("Client error: {}", e);
                process::exit(1);
            }
        }
        Commands::Keygen { private_key, public_key } => {
            let pub_key_path = public_key.unwrap_or_else(|| {
                let mut path = private_key.clone();
                path.set_extension("pub");
                path
            });
            
            println!("Generating SSH key pair...");
            match SshKeyPair::generate() {
                Ok(key_pair) => {
                    if let Err(e) = key_pair.save_public_key(&pub_key_path) {
                        eprintln!("Failed to save public key: {}", e);
                        process::exit(1);
                    }
                    println!("Public key saved to: {}", pub_key_path.display());
                    println!("Note: Private key saving not fully implemented in this demo");
                    println!("Key generation completed!");
                }
                Err(e) => {
                    eprintln!("Failed to generate key pair: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}
