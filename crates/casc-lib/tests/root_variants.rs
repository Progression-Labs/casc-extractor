//! Root variants and encrypted frames, against a real World of Warcraft install (read-only).
//!
//! All tests are `#[ignore]`. Run with:
//! `WOW_DIR=<install> WOW_LISTFILE=<community-listfile.csv> cargo test -p casc-lib --test root_variants -- --ignored`
//! `WOW_MISSING_WOWF` / `WOW_MISSING_CE` optionally name files of listfile paths (one per line)
//! that must all read in `wowf` / `wow_classic_era`.

use std::path::PathBuf;

use casc_lib::extract::{CascStorage, OpenConfig};
use casc_lib::root::flags::{ContentFlags, LocaleFlags};

fn open(product: &str) -> Option<CascStorage> {
    let install = PathBuf::from(std::env::var("WOW_DIR").ok()?);
    let listfile = PathBuf::from(std::env::var("WOW_LISTFILE").ok()?);
    Some(
        CascStorage::open(&OpenConfig {
            install_dir: install,
            product: Some(product.into()),
            keyfile: None,
            listfile: Some(listfile),
            output_dir: None,
        })
        .unwrap(),
    )
}

macro_rules! storage {
    ($product:expr) => {
        match open($product) {
            Some(s) => s,
            None => {
                eprintln!("SKIPPED: WOW_DIR / WOW_LISTFILE not set");
                return;
            }
        }
    };
}

#[test]
#[ignore]
fn standard_variant_when_high_res_is_not_installed() {
    let s = storage!("wowf");
    let (data, flags) = s
        .read_by_fdid_with_flags(127003, LocaleFlags::EN_US)
        .unwrap();
    assert_eq!(data.len(), 44_876);
    assert_eq!(&data[..4], b"BLP2");
    assert!(!flags.has(ContentFlags::HIGH_RES_TEXTURE));
}

#[test]
#[ignore]
fn high_res_variant_when_installed() {
    let s = storage!("wowf");
    let (data, flags) = s
        .read_by_fdid_with_flags(124154, LocaleFlags::EN_US)
        .unwrap();
    assert_eq!(data.len(), 12_108);
    assert!(flags.has(ContentFlags::HIGH_RES_TEXTURE));
}

fn every_listed_path_reads(product: &str, var: &str) {
    let Ok(list) = std::env::var(var) else {
        eprintln!("SKIPPED: {var} not set");
        return;
    };
    let s = storage!(product);
    let (mut ok, mut failed) = (0, Vec::new());
    for path in std::fs::read_to_string(list).unwrap().lines() {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        let fdid = s
            .listfile
            .fdid(path)
            .unwrap_or_else(|| panic!("{path} not in listfile"));
        match s.read_by_fdid(fdid, LocaleFlags::EN_US) {
            Ok(_) => ok += 1,
            Err(e) => failed.push(format!("{path} (fdid {fdid}): {e}")),
        }
    }
    eprintln!("{product}: {ok} read, {} failed", failed.len());
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

#[test]
#[ignore]
fn every_missing_wowf_path_reads() {
    every_listed_path_reads("wowf", "WOW_MISSING_WOWF");
}

#[test]
#[ignore]
fn every_missing_classic_era_path_reads() {
    every_listed_path_reads("wow_classic_era", "WOW_MISSING_CE");
}
