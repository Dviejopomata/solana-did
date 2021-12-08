#[macro_use]
extern crate log;

use std::iter;
use borsh::{BorshDeserialize, BorshSerialize, BorshSchema};
use yaml_rust::YamlLoader;
use std::fs;
use std::str::FromStr;
use solana_client::{blockhash_query::BlockhashQuery, rpc_client::RpcClient};
use image::Luma;
use qrcode::QrCode;
use env_logger::Env;
use env_logger::Builder;
use structopt::StructOpt;
use clap::{Arg, App, SubCommand};
use sol_did::{
    borsh as program_borsh,
    error::SolError,
    id, instruction,
    processor::process_instruction,
    state::{
        get_sol_address_with_seed, DecentralizedIdentifier, ServiceEndpoint, SolData,
        VerificationMethod,
    },
    validate_owner,
};
use sol_did::id as sol_did_id;
use solana_generator::discriminant::Discriminant;
use solana_generator::{build_instruction, Account, PDAGenerator, SolanaAccountMeta};
use log::{debug, error, log_enabled, info, Level};
use sol_did::instruction::SolInstruction;
use sol_did::solana_program::{system_program, sysvar};
use sol_did::solana_program::account_info::AccountInfo;
use solana_client::mock_sender::PUBKEY;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::entrypoint::ProgramResult;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_sdk::transaction::Transaction;
use challenge1::{Error, Result};

#[derive(StructOpt)]
struct Cli {
    #[structopt(short = "p", long = "pattern", help = "Pattern")]
    pattern: String,
}

struct Config {
    keypair: Keypair,
    json_rpc_url: String,
    verbose: bool,
}

fn main() {
    env_logger::init();
    let matches = App::new("DID CLI")
        .version("1.0")
        .author("David Viejo. <dviejo@kungfusoftware.es>")
        .about("Does awesome things")
        .subcommand(SubCommand::with_name("create")
            .about("creates a DID")
            .version("1.3")
            .author("Someone E. <someone_else@other.com>")
            .arg(Arg::with_name("debug")
                .short("d")
                .help("print debug information verbosely")))
        .get_matches();
    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::load(&"/home/dviejo/.config/solana/cli/config.yml").unwrap_or_default()
        };

        Config {
            json_rpc_url: matches
                .value_of("json_rpc_url")
                .unwrap_or(&cli_config.json_rpc_url)
                .to_string(),
            keypair: read_keypair_file(
                matches
                    .value_of("keypair")
                    .unwrap_or(&cli_config.keypair_path),
            ).unwrap(),
            verbose: matches.is_present("verbose"),
        }
    };

    let code = QrCode::new(b"did:sol:devnet:8khtkDMiZAXChwZNbKu4ugry1mdJ3d8RW6P62VD9UbA1").unwrap();

    let image = code.render::<image::Luma<u8>>().build();
    let file_path = "./qrcode.png";
    image.save(file_path).unwrap();
    info!("QR saved at {}", file_path);
    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    if let Some(matches) = matches.subcommand_matches("create") {
        if matches.is_present("debug") {
            debug!("Printing debug info...");
        } else {
            info!("Printing normally...");
        }
    }
    let rpc_client =
        RpcClient::new_with_commitment(config.json_rpc_url.clone(), CommitmentConfig::confirmed());
    let keypair_path = "/disco-grande/github-libs/sol-did/program/dist/sol_did-keypair.json";
    let payer = get_player().unwrap();
    let program = get_program(keypair_path, &rpc_client).unwrap();
    info!("{:?}", program);
    create_greeting_account(&payer, &program, &rpc_client).unwrap();
    let authority = Keypair::new();

    // let authority = player.pubkey();
    create_sol_account
    let (sol_account, _) = get_sol_address_with_seed(&authority.pubkey());
    let mut init_data = SolData::default();
    let endpoint = "http://localhost".to_string();
    let endpoint_type = "local".to_string();
    let description = "A localhost service".to_string();
    let service_endpoint = ServiceEndpoint {
        id: "service1".to_string(),
        endpoint_type,
        endpoint,
        description,
    };
    init_data.service = vec![service_endpoint.clone()];
    init_data.authority = authority.pubkey();

    let greeting_pubkey = get_greeting_public_key(&payer.pubkey(), &program.pubkey()).unwrap();
    // Transaction::new_signed_with_payer
    // let transaction = Transaction::new_signed_with_payer(
    //     &[instruction::initialize(
    //         &program.pubkey(),
    //         // &greeting_pubkey,
    //         &authority,
    //         SolData::DEFAULT_SIZE as u64,
    //         init_data,
    //     )],
    //     Some(&player.pubkey()),
    //     // Some(&greeting_pubkey),
    //     &[&program],
    //     rpc_client.get_recent_blockhash().unwrap().0,
    // );
    let instruction = Instruction::new_with_borsh(
        program.pubkey(),
        &SolInstruction::Initialize { size: SolData::DEFAULT_SIZE as u64, init_data },
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(sol_account, false),
            AccountMeta::new_readonly(authority.pubkey(), false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    );
    // let message = Message::new(&[instruction], Some(&player.pubkey()));
    // Self::new(signing_keypairs, message, recent_blockhash)
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        rpc_client.get_recent_blockhash().unwrap().0,
    );
    rpc_client.send_and_confirm_transaction(&transaction).unwrap();
    info!(
        "({}) greetings have been sent.",
        count_greetings(&payer, &program, &rpc_client).unwrap()
    );
}


fn check_authority(authority_info: &AccountInfo, did: &AccountInfo) -> Result<()> {
    let result = validate_owner(did, authority_info, iter::empty());
    Ok(())
}
/// Pulls down the greeting account data and the value of its counter
/// which ought to track how many times the `say_hello` method has
/// been run.
pub fn count_greetings(player: &Keypair, program: &Keypair, connection: &RpcClient) -> Result<u32> {
    let greeting_pubkey = get_greeting_public_key(&player.pubkey(), &program.pubkey())?;
    let greeting_account = connection.get_account(&greeting_pubkey)?;
    Ok(get_greeting_count(&greeting_account.data)?)
}

/// On Solana accounts are ways to store data. In order to use our
/// greeting counter smart contract we need some way to store the
/// number of times we have said hello to the contract. To do this we
/// create a greeting account which we subsequentally transfer
/// ownership of to the program. This allows the program to write to
/// that account as it deems fit.
///
/// The greeting account has a [derived
/// address](https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses)
/// which allows it to own and manage the account. Additionally the
/// address being derived means that we can regenerate it when we'd
/// like to find the greeting account again later.
pub fn create_greeting_account(
    player: &Keypair,
    program: &Keypair,
    connection: &RpcClient,
) -> Result<()> {
    let greeting_pubkey = get_greeting_public_key(&player.pubkey(), &program.pubkey())?;

    if let Err(_) = connection.get_account(&greeting_pubkey) {
        println!("creating greeting account");
        let lamport_requirement =
            connection.get_minimum_balance_for_rent_exemption(get_greeting_data_size()?)?;

        // This instruction creates an account with the key
        // "greeting_pubkey". The created account is owned by the
        // program. The account is loaded with enough lamports to stop
        // it from needing to pay rent. The lamports to fund this are
        // paid by the player.
        //
        // It is important that the program owns the created account
        // because it needs to be able to modify its contents.
        //
        // The address of the account created by
        // create_account_with_seed is the same as the address
        // generated by get_greeting_public_key. We do this as
        // opposed to create_account because create account doesn't
        // derive that address like that.
        let instruction = solana_sdk::system_instruction::create_account_with_seed(
            &player.pubkey(),
            &greeting_pubkey,
            &player.pubkey(),
            get_greeting_seed(),
            lamport_requirement,
            get_greeting_data_size()? as u64,
            &program.pubkey(),
        );
        let message = Message::new(&[instruction], Some(&player.pubkey()));
        let transaction =
            Transaction::new(&[player], message, connection.get_recent_blockhash()?.0);

        connection.send_and_confirm_transaction(&transaction)?;
    }

    Ok(())
}


/// Sends an instruction from PLAYER to PROGRAM via CONNECTION. The
/// instruction contains no data but does contain the address of our
/// previously generated greeting account. The program will use that
/// passed in address to update its greeting counter after verifying
/// that it owns the account that we have passed in.
pub fn initialize_did(player: &Keypair, authority: &Pubkey, program: &Keypair, connection: &RpcClient) -> Result<()> {
    let greeting_pubkey = get_greeting_public_key(&player.pubkey(), &program.pubkey())?;

    // Submit an instruction to the chain which tells the program to
    // run. We pass the account that we want the results to be stored
    // in as one of the accounts arguents which the program will
    // handle.
    let mut init_data = SolData::default();
    let sol_instruction = instruction::initialize(
        &player.pubkey(),
        &authority,
        1_000 as u64,
        init_data,
    );

    // let instruction = Instruction::new_with_bytes(
    //     program.pubkey(),
    //     sol_instruction.data.as_slice(),
    //     vec![AccountMeta::new(greeting_pubkey, false)],
    // );
    // let message = Message::new(&[instruction], Some(&player.pubkey()));
    // let transaction = Transaction::new(&[player], message, connection.get_recent_blockhash()?.0);
    // let transaction = Transaction::new_signed_with_payer(
    //     &[
    //         sol_instruction
    //     ],
    //     Some(&player.pubkey()),
    //     &[&player],
    //     connection.get_recent_blockhash()?.0,
    // );
    // connection.send_and_confirm_transaction(&transaction)?;

    Ok(())
}


/// Loads keypair information from the file located at KEYPAIR_PATH
/// and then verifies that the loaded keypair information corresponds
/// to an executable account via CONNECTION. Failure to read the
/// keypair or the loaded keypair corresponding to an executable
/// account will result in an error being returned.
pub fn get_program(keypair_path: &str, connection: &RpcClient) -> Result<Keypair> {
    let program_keypair = read_keypair_file(keypair_path).map_err(|e| {
        Error::InvalidConfig(format!(
            "failed to read program keypair file ({}): ({})",
            keypair_path, e
        ))
    })?;

    let program_info = connection.get_account(&program_keypair.pubkey())?;
    if !program_info.executable {
        return Err(Error::InvalidConfig(format!(
            "program with keypair ({}) is not executable",
            keypair_path
        )));
    }

    Ok(program_keypair)
}


/// The schema for greeting storage in greeting accounts. This is what
/// is serialized into the account and updated when hellos are sent.
#[derive(BorshSerialize, BorshDeserialize)]
struct GreetingSchema {
    counter: u32,
}

/// Parses and returns the Solana yaml config on the system.
pub fn get_config() -> Result<yaml_rust::Yaml> {
    let path = match home::home_dir() {
        Some(mut path) => {
            path.push(".config/solana/cli/config.yml");
            path
        }
        None => {
            return Err(Error::ConfigReadError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "failed to locate homedir and thus can not locoate solana config",
            )));
        }
    };
    let config = std::fs::read_to_string(path).map_err(|e| Error::ConfigReadError(e))?;
    let mut config = YamlLoader::load_from_str(&config)?;
    match config.len() {
        1 => Ok(config.remove(0)),
        l => Err(Error::InvalidConfig(format!(
            "expected one yaml document got ({})",
            l
        ))),
    }
}

/// Gets the RPC url for the cluster that this machine is configured
/// to communicate with.
pub fn get_rpc_url() -> Result<String> {
    let config = get_config()?;
    match config["json_rpc_url"].as_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::InvalidConfig(
            "missing `json_rpc_url` field".to_string(),
        )),
    }
}

/// Gets the "player" or local solana wallet that has been configured
/// on the machine.
pub fn get_player() -> Result<Keypair> {
    let config = get_config()?;
    let path = match config["keypair_path"].as_str() {
        Some(s) => s,
        None => {
            return Err(Error::InvalidConfig(
                "missing `keypair_path` field".to_string(),
            ));
        }
    };
    read_keypair_file(path).map_err(|e| {
        Error::InvalidConfig(format!("failed to read keypair file ({}): ({})", path, e))
    })
}

/// Gets the seed used to generate greeting accounts. If you'd like to
/// force this program to generate a new greeting account and thus
/// restart the counter you can change this value.
pub fn get_greeting_seed() -> &'static str {
    "hello"
}

/// Derives and returns the greeting account public key for a given
/// PLAYER, PROGRAM combination.
pub fn get_greeting_public_key(player: &Pubkey, program: &Pubkey) -> Result<Pubkey> {
    Ok(Pubkey::create_with_seed(
        player,
        get_greeting_seed(),
        program,
    )?)
}

/// Determines and reports the size of greeting data.
pub fn get_greeting_data_size() -> Result<usize> {
    let encoded = GreetingSchema { counter: 0 }
        .try_to_vec()
        .map_err(|e| Error::SerializationError(e))?;
    Ok(encoded.len())
}

/// Deserializes a greeting account and reports the value of its
/// greeting counter.
pub fn get_greeting_count(data: &[u8]) -> Result<u32> {
    let decoded = GreetingSchema::try_from_slice(data).map_err(|e| Error::SerializationError(e))?;
    Ok(decoded.counter)
}

