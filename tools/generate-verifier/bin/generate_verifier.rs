use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use eyre::{bail, Context, Result};
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    fs::write_evm_halo2_verifier_to_folder,
    prover::DeferralHookCommits,
    Sdk, OPENVM_VERSION,
};
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, hook_params_with_100_bits_security,
    MAX_APP_LOG_STACKED_HEIGHT,
};

#[derive(Parser, Debug)]
#[command(
    name = "generate-verifier",
    about = "Generate an OpenVM base or deferral Solidity verifier."
)]
struct Args {
    /// Directory that will receive src/v<OPENVM_VERSION>-<variant>.
    #[arg(long)]
    output_dir: PathBuf,

    /// Verifier variant to generate.
    #[arg(long, value_enum)]
    variant: Variant,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Variant {
    Base,
    Deferral,
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.run()
}

impl Args {
    fn run(&self) -> Result<()> {
        ensure_solc_installed()?;

        let version_dir = self.variant.version_dir_name();

        println!("Generating {version_dir} verifier");
        let sdk = self.variant.build_sdk()?;
        let verifier = sdk.generate_halo2_verifier_solidity_with_version_name(&version_dir)?;

        println!(
            "Writing verifier artifacts under {}",
            self.output_dir.display()
        );
        write_evm_halo2_verifier_to_folder(verifier, &self.output_dir, Some(&version_dir))
            .with_context(|| {
                format!(
                    "failed to write verifier under {}",
                    self.output_dir.display()
                )
            })?;

        Ok(())
    }
}

impl Variant {
    fn version_dir_name(self) -> String {
        match self {
            Variant::Base => format!("v{OPENVM_VERSION}-base"),
            Variant::Deferral => format!("v{OPENVM_VERSION}-deferral"),
        }
    }

    fn build_sdk(self) -> Result<Sdk> {
        let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
        let agg_params = AggregationSystemParams::default();

        match self {
            Variant::Base => {
                Sdk::new(AppConfig::riscv32(app_params), agg_params).map_err(Into::into)
            }
            Variant::Deferral => {
                let hook_params = hook_params_with_100_bits_security();
                let hook_commits =
                    DeferralHookCommits::from_system_params(&agg_params, hook_params);
                Sdk::builder()
                    .app_config(AppConfig::riscv32(app_params))
                    .agg_params(agg_params)
                    .deferral_hook_commits(hook_commits)
                    .build()
                    .map_err(Into::into)
            }
        }
    }
}

fn ensure_solc_installed() -> Result<()> {
    if std::process::Command::new("solc")
        .arg("--version")
        .output()
        .is_ok()
    {
        Ok(())
    } else {
        bail!("solc is not installed; install solc before generating verifier artifacts")
    }
}
