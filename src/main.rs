use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser};
use serde_json::to_writer_pretty;

mod uarp_parser;

use uarp_parser::{build_manifest, parse_uarp_from_bytes, ValidationMode};

/// Dump UARP "Super Binary" payloads.
#[derive(Parser, Debug)]
#[command(name = "uarp-dump", version = "1.1.0")]
#[command(about = "UARP 'Super Binary' container dumper (stride-preamble aware)")]
struct Cli {
    /// Path of the UARP file to process
    #[arg(value_name = "UARP_FILE", required = true)]
    uarp_file: PathBuf,

    /// Output directory (created if not exists)
    #[arg(short = 'o', long = "outdir", value_name = "DIR", default_value = "uarp_dump")]
    outdir: PathBuf,

    /// Overwrite into an existing directory without prompting
    #[arg(short = 'f', long = "force", action = ArgAction::SetTrue)]
    force: bool,

    /// Verbose: list tags/versions/sizes as they are written
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Dump the global metadata block (if present) to 'global_metadata.bin'
    #[arg(long = "dump-global-metadata", action = ArgAction::SetTrue)]
    dump_global_metadata: bool,

    /// Dump the global TLVs to 'global_metadata.json' (requires --parse-tlv)
    #[arg(long = "dump-global-metadata-json", action = ArgAction::SetTrue)]
    dump_global_metadata_json: bool,

    /// Dump per‑payload metadata (if present) to '<tag>_meta.bin'
    #[arg(long = "dump-payload-metadata", action = ArgAction::SetTrue)]
    dump_payload_metadata: bool,

    /// Emit a JSON manifest describing header, payload headers, and TLVs (where decodable)
    #[arg(long = "emit-json", value_name = "FILE")]
    emit_json: Option<PathBuf>,

    /// Attempt TLV parsing for metadata blocks (non-fatal if not TLV)
    #[arg(long = "parse-tlv", action = ArgAction::SetTrue)]
    parse_tlv: bool,

    /// Relax validation to header-only checks
    #[arg(long = "header-only", action = ArgAction::SetTrue)]
    header_only: bool,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    // Read entire file
    let mut f = fs::File::open(&cli.uarp_file)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;

    // Parse & validate
    let mode = ValidationMode {
        header_only: cli.header_only,
        parse_tlv: cli.parse_tlv,
    };

    let uarp = parse_uarp_from_bytes(&bytes, mode)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Prepare output dir
    if cli.outdir.exists() {
        if !cli.force && !is_empty_dir(&cli.outdir)? {
            eprintln!(
                "Error: directory {:?} exists and is not empty. Pass '-f' to proceed.",
                &cli.outdir
            );
            return Ok(());
        }
    } else {
        fs::create_dir_all(&cli.outdir)?;
    }

    // Dump global metadata if requested
    if cli.dump_global_metadata {
        if let Some(raw) = &uarp.global_metadata_raw {
            let path = cli.outdir.join("global_metadata.bin");
            fs::write(&path, raw)?;
            if cli.verbose {
                println!("global_metadata.bin: {} bytes", raw.len());
            }
        }
    }
    if cli.dump_global_metadata_json {
        if let Some(tlvs) = &uarp.global_metadata_tlvs {
            let path = cli.outdir.join("global_metadata.json");
            let f = fs::File::create(&path)?;
            to_writer_pretty(f, &tlvs.iter().map(|t| t.to_view()).collect::<Vec<_>>())
                .map_err(to_io)?;
            if cli.verbose {
                println!("global_metadata.json: {} TLVs", tlvs.len());
            }
        } else {
            eprintln!("global metadata is not TLV or --parse-tlv not enabled; no JSON emitted");
        }
    }

    // Dump payload data and metadata
    let mut total: u64 = 0;
    for (idx, p) in uarp.payloads.iter().enumerate() {
        let fname = safe_tag_filename(&p.header.payload_tag, idx);
        let out = cli.outdir.join(&fname);
        fs::write(&out, &p.data)?;
        total += p.data.len() as u64;

        if cli.verbose {
            println!(
                "{}: {} bytes (offset={}, length={})  v{}.{}.{}+{}  meta(off={}, len={})",
                tag_to_string(&p.header.payload_tag),
                p.data.len(),
                p.header.payload_data_offset,
                p.header.payload_data_length,
                p.header.version_major,
                p.header.version_minor,
                p.header.version_release,
                p.header.version_build,
                p.header.payload_meta_offset,
                p.header.payload_meta_length
            );
        }

        if cli.dump_payload_metadata {
            if let Some(meta_raw) = &p.metadata_raw {
                let meta_name = format!("{}_meta.bin", fname);
                fs::write(cli.outdir.join(meta_name), meta_raw)?;
            }
        }
    }

    // Emit JSON manifest (headers + TLVs where decodable)
    if let Some(path) = &cli.emit_json {
        let f = fs::File::create(path)?;
        to_writer_pretty(f, &build_manifest(&uarp)).map_err(to_io)?;
        if cli.verbose {
            println!("manifest JSON written to {:?}", path);
        }
    }

    println!(
        "✔ wrote {} payloads with total of {} bytes",
        uarp.payloads.len(),
        total
    );

    Ok(())
}

fn is_empty_dir(p: &Path) -> io::Result<bool> {
    if !p.is_dir() {
        return Ok(false);
    }
    for e in fs::read_dir(p)? {
        let _ = e?;
        return Ok(false);
    }
    Ok(true)
}

fn to_io<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

fn tag_to_string(tag4: &[u8; 4]) -> String {
    let ascii_ok = tag4.iter().all(|b| (0x20..=0x7E).contains(b));
    if ascii_ok {
        String::from_utf8_lossy(tag4).to_string()
    } else {
        format!("{:02X}{:02X}{:02X}{:02X}", tag4[0], tag4[1], tag4[2], tag4[3])
    }
}

fn safe_tag_filename(tag4: &[u8; 4], index: usize) -> String {
    let ascii_ok = tag4.iter().all(|b| (0x20..=0x7E).contains(b));
    if ascii_ok {
        if index == 0 {
            String::from_utf8_lossy(tag4).to_string()
        } else {
            format!("{}_{index}", String::from_utf8_lossy(tag4))
        }
    } else if index == 0 {
        format!("{:02X}{:02X}{:02X}{:02X}", tag4[0], tag4[1], tag4[2], tag4[3])
    } else {
        format!("{:02X}{:02X}{:02X}{:02X}_{index}", tag4[0], tag4[1], tag4[2], tag4[3])
    }
}
