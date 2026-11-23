use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use nvidia_attestation_runner::{
    CcAdminRunner, NvAttestRunner, NvidiaAttestationBackend, NvidiaEvidenceBundle,
    NvidiaGpuEvidenceSummaryV1, Policy, PolicyVerdict,
};
use serde::Serialize;

enum Command {
    Run(Args),
    Help,
}

#[derive(Debug)]
struct Args {
    backend: NvidiaAttestationBackend,
    nonce_hex: String,
    program: Option<OsString>,
    command_args: Vec<OsString>,
    pretty: bool,
    no_policy: bool,
    allow_policy_failure: bool,
    summary_only: bool,
    summary_file: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct CliOutput {
    bundle_sha256: String,
    summary_sha256: String,
    summary: NvidiaGpuEvidenceSummaryV1,
    policy: Option<PolicyVerdict>,
    bundle: NvidiaEvidenceBundle,
}

#[derive(Debug, Serialize)]
struct SummaryCliOutput {
    summary_sha256: String,
    summary: NvidiaGpuEvidenceSummaryV1,
}

fn main() -> ExitCode {
    match run() {
        Ok(accepted) => {
            if accepted {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<bool, Box<dyn Error>> {
    let args = match Command::parse(env::args_os().skip(1))? {
        Command::Run(args) => args,
        Command::Help => {
            print_usage();
            return Ok(true);
        }
    };
    let bundle = run_backend(&args)?;
    let policy_name = if args.no_policy {
        "none"
    } else {
        policy_name_for_backend(args.backend)
    };
    let policy = if args.no_policy {
        None
    } else {
        Some(
            policy_for_backend(args.backend)
                .expected_nonce_hex(&args.nonce_hex)?
                .evaluate(bundle.report()),
        )
    };
    let accepted = policy
        .as_ref()
        .map(|verdict| verdict.accepted)
        .unwrap_or(true);
    let summary = bundle.gpu_evidence_summary(policy_name, policy.as_ref());
    let summary_sha256 = summary.canonical_json_sha256_hex()?;
    if let Some(path) = &args.summary_file {
        let bytes = if args.pretty {
            serde_json::to_vec_pretty(&SummaryCliOutput {
                summary_sha256: summary_sha256.clone(),
                summary: summary.clone(),
            })?
        } else {
            serde_json::to_vec(&SummaryCliOutput {
                summary_sha256: summary_sha256.clone(),
                summary: summary.clone(),
            })?
        };
        fs::write(path, bytes)?;
    }

    if args.summary_only {
        let output = SummaryCliOutput {
            summary_sha256,
            summary,
        };
        if args.pretty {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{}", serde_json::to_string(&output)?);
        }
        return Ok(accepted || args.allow_policy_failure);
    }

    let output = CliOutput {
        bundle_sha256: bundle.canonical_json_sha256_hex()?,
        summary_sha256,
        summary,
        policy,
        bundle,
    };

    if args.pretty {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", serde_json::to_string(&output)?);
    }

    Ok(accepted || args.allow_policy_failure)
}

fn run_backend(args: &Args) -> Result<NvidiaEvidenceBundle, Box<dyn Error>> {
    match args.backend {
        NvidiaAttestationBackend::NvAttestLocalJson => {
            Ok(NvAttestRunner::local_gpu_with_nonce_hex(&args.nonce_hex).run_local_gpu_bundle()?)
        }
        NvidiaAttestationBackend::NvAttestRemoteJson => {
            Ok(NvAttestRunner::remote_gpu_with_nonce_hex(&args.nonce_hex)
                .run_remote_gpu_bundle()?)
        }
        NvidiaAttestationBackend::CcAdminTranscript => {
            Ok(CcAdminRunner::python_module_with_nonce_hex(&args.nonce_hex).run_bundle()?)
        }
        NvidiaAttestationBackend::CustomJson => {
            let runner = custom_json_runner(args)?;
            Ok(runner.run_bundle_with_backend(NvidiaAttestationBackend::CustomJson)?)
        }
        NvidiaAttestationBackend::CustomTranscript => {
            let runner = custom_transcript_runner(args)?;
            Ok(runner.run_bundle_with_backend(NvidiaAttestationBackend::CustomTranscript)?)
        }
    }
}

fn custom_json_runner(args: &Args) -> Result<NvAttestRunner, Box<dyn Error>> {
    let program = args
        .program
        .clone()
        .ok_or("--program is required for custom-json")?;
    Ok(NvAttestRunner::new(program).args(args.command_args.clone()))
}

fn custom_transcript_runner(args: &Args) -> Result<CcAdminRunner, Box<dyn Error>> {
    let program = args
        .program
        .clone()
        .ok_or("--program is required for custom-transcript")?;
    Ok(CcAdminRunner::new(program).args(args.command_args.clone()))
}

fn policy_for_backend(backend: NvidiaAttestationBackend) -> Policy {
    match backend {
        NvidiaAttestationBackend::NvAttestLocalJson
        | NvidiaAttestationBackend::NvAttestRemoteJson
        | NvidiaAttestationBackend::CustomJson => Policy::nvidia_cc_baseline(),
        NvidiaAttestationBackend::CcAdminTranscript
        | NvidiaAttestationBackend::CustomTranscript => {
            Policy::nvidia_cc_admin_transcript_baseline()
        }
    }
}

fn policy_name_for_backend(backend: NvidiaAttestationBackend) -> &'static str {
    match backend {
        NvidiaAttestationBackend::NvAttestLocalJson
        | NvidiaAttestationBackend::NvAttestRemoteJson
        | NvidiaAttestationBackend::CustomJson => "nvidia_cc_baseline",
        NvidiaAttestationBackend::CcAdminTranscript
        | NvidiaAttestationBackend::CustomTranscript => "nvidia_cc_admin_transcript_baseline",
    }
}

impl Command {
    fn parse<I>(input: I) -> Result<Self, Box<dyn Error>>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut backend = None;
        let mut nonce_hex = None;
        let mut program = None;
        let mut command_args = Vec::new();
        let mut pretty = false;
        let mut no_policy = false;
        let mut allow_policy_failure = false;
        let mut summary_only = false;
        let mut summary_file = None;

        let mut args = input.into_iter();
        while let Some(arg) = args.next() {
            match arg.to_string_lossy().as_ref() {
                "-h" | "--help" => return Ok(Self::Help),
                "--backend" => backend = Some(parse_backend(next_arg(&mut args, "--backend")?)?),
                "--nonce" => {
                    nonce_hex = Some(
                        next_arg(&mut args, "--nonce")?
                            .to_string_lossy()
                            .into_owned(),
                    )
                }
                "--program" => program = Some(next_arg(&mut args, "--program")?),
                "--arg" => command_args.push(next_arg(&mut args, "--arg")?),
                "--pretty" => pretty = true,
                "--no-policy" => no_policy = true,
                "--allow-policy-failure" => allow_policy_failure = true,
                "--summary-only" => summary_only = true,
                "--summary-file" => {
                    summary_file = Some(PathBuf::from(next_arg(&mut args, "--summary-file")?))
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }

        let backend = backend.ok_or("--backend is required")?;
        let nonce_hex = nonce_hex.ok_or("--nonce is required")?;
        validate_nonce_hex(&nonce_hex)?;

        Ok(Self::Run(Args {
            backend,
            nonce_hex,
            program,
            command_args,
            pretty,
            no_policy,
            allow_policy_failure,
            summary_only,
            summary_file,
        }))
    }
}

fn next_arg<I>(args: &mut I, flag: &str) -> Result<OsString, Box<dyn Error>>
where
    I: Iterator<Item = OsString>,
{
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_backend(value: OsString) -> Result<NvidiaAttestationBackend, Box<dyn Error>> {
    match value.to_string_lossy().as_ref() {
        "nvattest-local-json" => Ok(NvidiaAttestationBackend::NvAttestLocalJson),
        "nvattest-remote-json" => Ok(NvidiaAttestationBackend::NvAttestRemoteJson),
        "cc-admin-transcript" => Ok(NvidiaAttestationBackend::CcAdminTranscript),
        "custom-json" => Ok(NvidiaAttestationBackend::CustomJson),
        "custom-transcript" => Ok(NvidiaAttestationBackend::CustomTranscript),
        other => Err(format!("unknown backend: {other}").into()),
    }
}

fn validate_nonce_hex(nonce_hex: &str) -> Result<(), Box<dyn Error>> {
    let nonce = nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex);
    if nonce.len() != 64 || !nonce.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("--nonce must be 32 bytes encoded as 64 hex characters".into());
    }
    Ok(())
}

fn print_usage() {
    println!(
        "Usage: nvidia-attestation-runner --backend <backend> --nonce <64-hex> [options]\n\
\n\
Backends:\n\
  nvattest-local-json       Run nvattest local GPU JSON appraisal\n\
  nvattest-remote-json      Run nvattest remote GPU JSON appraisal\n\
  cc-admin-transcript       Run python3 -m verifier.cc_admin --verbose\n\
  custom-json               Run --program with repeated --arg values and parse JSON stdout\n\
  custom-transcript         Run --program with repeated --arg values and parse cc_admin-like stdout\n\
\n\
Options:\n\
  --program <path>          Required for custom-* backends\n\
  --arg <value>             Add one custom command argument; repeat as needed\n\
  --pretty                  Pretty-print JSON output\n\
  --no-policy               Emit bundle without policy evaluation\n\
  --allow-policy-failure    Exit 0 even when policy rejects the evidence\n\
  --summary-only            Emit only the redacted GPU evidence summary\n\
  --summary-file <path>     Also write the redacted summary JSON to this path\n"
    );
}
