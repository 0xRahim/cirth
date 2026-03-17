use clap::Parser;
use goblin::{elf::header::*, mach::Mach, Object};
use memchr::memmem;
use object::{Object as ObjTrait, ObjectSymbol};
use serde::Serialize;
use std::{fs, io, path::PathBuf};

/// Simple CLI for binary static analysis.
#[derive(Parser, Debug)]
#[command(author, version, about = "Binary static analysis tool", long_about = None)]
struct Args {
    /// Path to the binary file to analyze
    file: PathBuf,

    /// Output JSON (default: false -> human readable)
    #[arg(short, long)]
    json: bool,
}

#[derive(Serialize, Debug)]
struct AnalysisReport {
    path: String,
    format: String,
    os: String,
    arch: String,
    is_dynamic: Option<bool>,
    is_stripped: Option<bool>,
    probable_language: Option<String>,
    packed: Option<bool>,
    anti_debug_indicators: Vec<String>,
    imports: Vec<String>,
    imported_libraries: Vec<String>,
    strings: Vec<String>,
    notes: Vec<String>,
}

fn main() {
    let args = Args::parse();

    match run(&args.file) {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => println!("{}", s),
                    Err(e) => eprintln!("Failed to serialize report: {}", e),
                }
            } else {
                print_report_human(&report);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Top-level orchestration function
fn run(path: &PathBuf) -> io::Result<AnalysisReport> {
    let bytes = fs::read(path)?;
    let filename = path.to_string_lossy().to_string();

    // quick format detection using goblin object
    let format = match Object::parse(&bytes) {
        Ok(Object::Elf(_)) => "ELF".to_string(),
        Ok(Object::PE(_)) => "PE".to_string(),
        Ok(Object::Mach(_)) => "Mach-O".to_string(),
        Ok(Object::Archive(_)) => "Archive".to_string(),
        Ok(Object::Unknown(_)) => "Unknown".to_string(), // ✅ ADD THIS
        Err(_) => {
            if bytes.starts_with(b"MZ") {
                "PE (maybe)".to_string()
            } else if bytes.starts_with(b"\x7fELF") {
                "ELF (by magic)".to_string()
            } else {
                "Unknown".to_string()
            }
        }
    };

    // fields to populate
    let mut os = "Unknown".to_string();
    let mut arch = "Unknown".to_string();
    let mut is_dynamic: Option<bool> = None;
    let mut is_stripped: Option<bool> = None;
    let mut imports: Vec<String> = Vec::new();
    let mut imported_libraries: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Use goblin for format-specific details, and object for symbol scanning
    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            os = "Linux/Unix".to_string();
            arch = match elf.header.e_machine {
                EM_386 => "x86".to_string(),
                EM_X86_64 => "x86_64".to_string(),
                EM_ARM => "arm".to_string(),
                EM_AARCH64 => "aarch64".to_string(),
                other => format!("unknown ({})", other),
            };

            // dynamic if dynamic segment present or DT_NEEDED exists
            is_dynamic = Some(!elf.libraries.is_empty() || elf.program_headers.iter().any(|ph| ph.p_type == goblin::elf::program_header::PT_DYNAMIC));

            // stripped: heuristics - if there are no full symbol table entries (.symtab) then likely stripped
            is_stripped = Some(elf.syms.is_empty());

            // libraries (DT_NEEDED)
            for lib in &elf.libraries {
                imported_libraries.push(lib.to_string());
            }

            // dynamic symbol names
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    imports.push(name.to_string());
                }
            }
        }
        Ok(Object::PE(pe)) => {
            os = "Windows".to_string();

            arch = match pe.header.coff_header.machine {
                goblin::pe::header::COFF_MACHINE_X86 => "x86".to_string(),
                goblin::pe::header::COFF_MACHINE_X86_64 => "x86_64".to_string(),
                goblin::pe::header::COFF_MACHINE_ARM => "arm".to_string(),
                goblin::pe::header::COFF_MACHINE_ARM64 => "aarch64".to_string(),
                other => format!("unknown ({})", other),
            };

            // dynamic if imports present
            is_dynamic = Some(!pe.imports.is_empty());

            // exported functions = pe.exports; debug_data is Option
            let has_exports = !pe.exports.is_empty();
            let has_debug = pe.debug_data.is_some();
            is_stripped = Some(!has_exports && !has_debug);

            // imports - each import has dll and name
            for imp in &pe.imports {
                imported_libraries.push(imp.dll.to_string());
                // imp.name is usually a string-like type (Cow or String) - push it
                imports.push(imp.name.to_string());
            }
        }
        Ok(Object::Mach(mach)) => {
            os = "macOS".to_string();
            match mach {
                Mach::Fat(fat) => {
                    // fat binary: collect archs (best-effort)
                    let mut arches = Vec::new();
                
                    // `fat.arches()` returns a slice/Vec of `FatArch`. Different goblin versions expose slightly
                    // different fields; rather than rely on a specific field name, use the Debug representation
                    // so this compiles across versions and still gives useful information.
                    for arch_hdr in fat.arches().iter() {
                        arches.push(format!("{:?}", arch_hdr));
                    }
                
                    arch = format!("Fat: {:?}", arches);
                    is_dynamic = Some(true);
                }
                Mach::Binary(mb) => {
                    arch = format!("{:?}", mb.header.cputype);
                    // dynamic if there's a LC_LOAD_DYLIB etc.
                    is_dynamic = Some(mb.load_commands.iter().any(|lc| {
                        use goblin::mach::load_command::CommandVariant;
                        matches!(&lc.command, CommandVariant::LoadDylib(_) | CommandVariant::LoadWeakDylib(_) | CommandVariant::LoadUpwardDylib(_))
                    }));

                    // Try to gather load commands (best-effort). Avoid calling methods that may not exist; format for debug instead.
                    use goblin::mach::load_command::CommandVariant;
                    for lc in &mb.load_commands {
                        if let CommandVariant::LoadDylib(d) = &lc.command {
                            // DylibCommand doesn't necessarily expose a convenient name() on all goblin versions;
                            // push a debug representation to avoid calling absent methods.
                            imported_libraries.push(format!("{:?}", d));
                        } else if let CommandVariant::LoadWeakDylib(d) = &lc.command {
                            imported_libraries.push(format!("{:?}", d));
                        }
                    }

                    // Collect defined/undefined symbols via object crate below (generic)
                }
            }
        }
        Ok(Object::Archive(_)) => {
            notes.push("Archive (static library) detected".to_string());
            // typical .a archives: treat as static
            is_dynamic = Some(false);
        }
        Err(_) => {
            notes.push("Could not parse with goblin; using generic heuristics".to_string());
        }
        Ok(Object::Unknown(_)) => {
            notes.push("Unknown binary format".to_string());
        }
    }

    // Generic symbol & import scan using `object` (works across formats). This complements goblin findings.
    if let Ok(obj_file) = object::File::parse(&*bytes) {
        // architecture (fallback or more consistent)
        arch = match obj_file.architecture() {
            object::Architecture::I386 => "x86".to_string(),
            object::Architecture::X86_64 => "x86_64".to_string(),
            object::Architecture::Aarch64 => "aarch64".to_string(),
            object::Architecture::Arm => "arm".to_string(),
            other => format!("{:?}", other),
        };

        // collect undefined symbols (imports) and also collect symbol names (avoid duplicates)
        for sym in obj_file.symbols() {
            if let Ok(name) = sym.name() {
                // undefined symbols are likely imports
                if sym.is_undefined() {
                    imports.push(name.to_string());
                } else {
                    // keep global/local symbols too if they look like imports (best-effort)
                    // (optional) skip to avoid huge lists
                }
            }
        }

        // object::File does expose imports for some formats; we try to gather library names if present
        // but not all formats expose this across versions, so we keep goblin's libraries where available.
    } else {
        notes.push("object::File parse failed; skipping generic symbol scan".to_string());
    }

    // Deduplicate imports & imported_libraries (preserve order)
    imports = dedup_preserve_order(imports);
    imported_libraries = dedup_preserve_order(imported_libraries);

    // Extract printable strings
    let strings = extract_strings(&bytes, 4);

    // Packed detection: UPX marker or high entropy
    let mut packed = false;
    if memmem::find(&bytes, b"UPX!").is_some() {
        packed = true;
        notes.push("UPX marker found".to_string());
    }
    let entropy = shannon_entropy(&bytes);
    if entropy > 7.5 {
        packed = true;
        notes.push(format!("Overall high entropy: {:.3} (heuristic)", entropy));
    } else {
        notes.push(format!("Entropy: {:.3}", entropy));
    }

    // Anti-debug heuristics
    let anti_debug_indicators = detect_anti_debug(&imports, &strings);

    // Language inference
    let probable_language = infer_language(&strings, &imports);

    // Merge imports with strings heuristics for common functions
    let mut imported_names = imports.clone();
    for s in &strings {
        let s_lower = s.to_lowercase();
        for &fn_name in &[
            "printf", "scanf", "fopen", "open", "read", "write", "execve", "system", "createprocess",
            "isdebuggerpresent", "ptrace",
        ] {
            if s_lower.contains(fn_name) && !imported_names.iter().any(|x| x.eq_ignore_ascii_case(fn_name)) {
                imported_names.push(fn_name.to_string());
            }
        }
    }
    imported_names = dedup_preserve_order(imported_names);

    let report = AnalysisReport {
        path: filename,
        format,
        os,
        arch,
        is_dynamic,
        is_stripped,
        probable_language,
        packed: Some(packed),
        anti_debug_indicators,
        imports: imported_names,
        imported_libraries,
        strings,
        notes,
    };

    Ok(report)
}

/// Human readable print of report
fn print_report_human(r: &AnalysisReport) {
    println!("Binary analysis report for: {}\n", r.path);
    println!("Format: {}\nOS: {}\nArch: {}", r.format, r.os, r.arch);
    println!("Dynamic-linked: {}", r.is_dynamic.map(|b| b.to_string()).unwrap_or("unknown".to_string()));
    println!("Stripped: {}", r.is_stripped.map(|b| b.to_string()).unwrap_or("unknown".to_string()));
    println!("Probable language: {}", r.probable_language.clone().unwrap_or("unknown".to_string()));
    println!("Packed (heuristic): {}", r.packed.map(|b| b.to_string()).unwrap_or("unknown".to_string()));
    println!("\nAnti-debug indicators (heuristic):");
    if r.anti_debug_indicators.is_empty() {
        println!("  None found (heuristic)");
    } else {
        for i in &r.anti_debug_indicators {
            println!("  - {}", i);
        }
    }
    println!("\nImported libraries:");
    for lib in &r.imported_libraries {
        println!("  - {}", lib);
    }
    println!("\nImported functions / names (sample up to 40):");
    for f in r.imports.iter().take(40) {
        println!("  - {}", f);
    }
    println!("\nExtracted strings (sample up to 40):");
    for s in r.strings.iter().take(40) {
        println!("  - {}", s);
    }
    if !r.notes.is_empty() {
        println!("\nNotes:");
        for n in &r.notes {
            println!("  - {}", n);
        }
    }
}

/// Extract printable ASCII/UTF-8-like strings of minimal length `min_len`
fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut res = Vec::new();
    let mut cur = Vec::new();

    for &b in bytes {
        if (b >= 0x20 && b <= 0x7e) || b == b'\n' || b == b'\r' || b == b'\t' {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        res.push(s);
                    }
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = String::from_utf8(cur.clone()) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                res.push(s);
            }
        }
    }

    dedup_preserve_order(res)
}

/// Compute Shannon entropy for provided bytes (0..8)
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut ent = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / len;
        ent -= p * p.log2();
    }
    ent
}

/// Heuristic detection of anti-debugging: look for imported symbols and strings commonly used in anti-debugging code.
fn detect_anti_debug(imports: &Vec<String>, strings: &Vec<String>) -> Vec<String> {
    let mut hits = Vec::new();
    // common Windows API
    let win_checks = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess"];
    for &w in &win_checks {
        if imports.iter().any(|s| s.contains(w)) || strings.iter().any(|s| s.contains(w)) {
            hits.push(format!("Found Windows anti-debug API: {}", w));
        }
    }
    // common linux ptrace
    if imports.iter().any(|s| s.to_lowercase().contains("ptrace")) || strings.iter().any(|s| s.to_lowercase().contains("ptrace")) {
        hits.push("ptrace usage found (possible anti-debug)".to_string());
    }

    // looking for anti-debugging patterns in strings
    let anti_keywords = ["debugger", "trap", "int3", "is_debugger", "check_debug", "anti_debug", "AntiDebug"];
    for k in &anti_keywords {
        if strings.iter().any(|s| s.to_lowercase().contains(&k.to_lowercase())) {
            hits.push(format!("String containing '{}'", k));
        }
    }

    hits
}

/// Infer programming language from strings & imports (heuristic)
fn infer_language(strings: &Vec<String>, imports: &Vec<String>) -> Option<String> {
    for s in strings.iter() {
        if s.starts_with("go-buildid:") || s.contains("go1.") || s.contains("golang") || s.contains("runtime.main") {
            return Some("Go".to_string());
        }
    }
    for s in strings.iter() {
        if s.contains("rust_eh_personality") || s.contains("rust_begin_unwind") || s.contains("RUSTC") {
            return Some("Rust".to_string());
        }
    }
    for s in imports.iter().chain(strings.iter()) {
        if s.starts_with("_Z") {
            return Some("C++".to_string());
        }
    }
    let mut c_like = 0;
    let mut cpp_like = 0;
    for s in imports.iter().chain(strings.iter()) {
        let s_low = s.to_lowercase();
        if s_low.contains("printf") || s_low.contains("scanf") || s_low.contains("fopen") {
            c_like += 1;
        }
        if s_low.starts_with("_z") {
            cpp_like += 1;
        }
    }
    if cpp_like > c_like && cpp_like > 0 {
        return Some("C++".to_string());
    } else if c_like > 0 {
        return Some("C".to_string());
    }
    None
}

/// Deduplicate while preserving order
fn dedup_preserve_order(mut v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
    v
}