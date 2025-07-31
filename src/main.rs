use anyhow::{Context, Result, bail};
use clap::Parser;
use object::ObjectSymbol;
use object::write::{
    self as writeobj, Object, Relocation, SectionId, Symbol, SymbolFlags, SymbolId, SymbolSection,
};
use object::{
    BinaryFormat, Endianness, File, Object as _, ObjectKind, ObjectSection, RelocationTarget,
    SectionKind, SymbolKind, SymbolScope,
};
use rand::Rng as _;
use rand::rng;
use std::collections::HashMap;
use std::fs::File as FsFile;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::PathBuf;

/// A utility for mangling names in static object files. Mainly useful for leakage of non-exported symbols in Rust static libraries.
/// (see https://github.com/rust-lang/rust/issues/104707)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    input: PathBuf,

    #[clap(short, long)]
    output: PathBuf,

    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "__rust_no_alloc_shim_is_unstable,rust_eh_personality"
    )]
    symbols: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input_path = args.input;
    let output_lib = args.output;
    let symbols_to_rename = args.symbols;

    println!("-> Input file: {input_path:?}");
    println!("-> Output .lib: {output_lib:?}");
    println!("-> Symbols to rename: {symbols_to_rename:?}");

    if !input_path.exists() {
        bail!("Input file does not exist: {:?}", input_path);
    }

    // prepare temp dir
    let lib_stem = output_lib
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("patched");
    let parent = output_lib.parent().unwrap_or(std::path::Path::new("."));
    let temp_dir = parent.join(format!("{lib_stem}_objs"));
    if temp_dir.exists() {
        if !temp_dir.is_dir() {
            bail!("Temp path exists but is not a directory: {:?}", temp_dir);
        }
        for e in std::fs::read_dir(&temp_dir)
            .with_context(|| format!("Failed to read temp dir {temp_dir:?}"))?
        {
            let e = e?;
            if e.file_type()?.is_file() {
                let _ = std::fs::remove_file(e.path());
            }
        }
    } else {
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("Failed to create temp dir {temp_dir:?}"))?;
    }

    let suffix: String = {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const LEN: usize = 8;
        let mut r = rng();
        let mut s = String::with_capacity(LEN);
        for _ in 0..LEN {
            let idx = r.random_range(0..CHARS.len());
            s.push(CHARS[idx] as char);
        }
        s
    };
    println!("-> Using unique suffix: _{suffix}");

    // emit objs
    let input_file_for_iter = FsFile::open(&input_path)
        .with_context(|| format!("Failed to open input file for iteration {input_path:?}"))?;
    let mut archive = ar::Archive::new(input_file_for_iter);

    let mut written_paths: Vec<std::path::PathBuf> = Vec::new();

    while let Some(entry_result) = archive.next_entry() {
        let mut entry = entry_result.context("Failed to read archive entry")?;
        let identifier = String::from_utf8_lossy(entry.header().identifier()).to_string();

        let mut data = Vec::with_capacity(entry.header().size() as usize);
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("Failed to read archive member: {identifier}"))?;

        let patched = match patch_object_file(&data, &symbols_to_rename, &suffix) {
            Ok(new_data) => {
                println!("   - Patched symbols in object: {identifier}");
                new_data
            }
            Err(err) => {
                println!("   - Skipping member: {identifier} ({err})");
                continue;
            }
        };

        // filter out non-object members if they are parsed somehow
        let lower = identifier.to_ascii_lowercase();
        if lower.ends_with(".dll") || lower.contains(".dll/") || lower.contains(".dll\\") {
            println!("   - Ignoring non-object member: {identifier}");
            continue;
        }

        // extract base name
        let base_name = identifier
            .rsplit('/')
            .next()
            .unwrap_or(identifier.as_str())
            .rsplit('\\')
            .next()
            .unwrap_or(identifier.as_str());

        // sanitize
        let mut stem = base_name.replace([':', '*', '?'], "_");
        stem = stem.replace(['"', '<', '>', '|'], "_");
        if let Some(pos) = stem.rfind('.') {
            stem.truncate(pos);
        }
        if stem.is_empty() {
            stem = "member".to_string();
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        identifier.hash(&mut hasher);
        let short_hash = (hasher.finish() & u32::MAX as u64) as u32;

        let out_name = format!("{stem}.{short_hash}.obj");

        let mut out_path = temp_dir.clone();
        out_path.push(out_name);

        std::fs::write(&out_path, &patched).with_context(|| {
            format!("Failed to write patched object to {out_path:?} (source member: {identifier})")
        })?;

        written_paths.push(out_path);
    }

    if written_paths.is_empty() {
        bail!("No COFF relocatable members were found or patched. Nothing to archive.");
    }

    println!(
        "-> Wrote {} patched .obj file(s) into temp directory: {:?}",
        written_paths.len(),
        temp_dir
    );

    // link
    let output_lib_abs = std::fs::canonicalize(&output_lib).unwrap_or(output_lib.clone());
    let temp_dir_abs = std::fs::canonicalize(&temp_dir).unwrap_or(temp_dir.clone());

    let mut tried = Vec::new();
    let mut archive_ok = false;

    fn run(
        cmd: &str,
        args: &[&str],
        workdir: &std::path::Path,
    ) -> std::io::Result<(std::process::ExitStatus, String, String)> {
        use std::process::Command;
        let output = Command::new(cmd).args(args).current_dir(workdir).output()?;
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        Ok((output.status, out, err))
    }

    let mut obj_rel_args: Vec<String> = Vec::with_capacity(written_paths.len());
    for p in &written_paths {
        let rel = p
            .strip_prefix(&temp_dir_abs)
            .map(|rp| rp.to_path_buf())
            .unwrap_or_else(|_| {
                p.file_name()
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| p.clone())
            });
        obj_rel_args.push(rel.to_string_lossy().to_string());
    }

    // try lib.exe
    let rsp_path = temp_dir_abs.join("archive.rsp");
    {
        let mut rsp = String::new();
        rsp.push_str("/nologo\n");
        rsp.push_str(&format!("/OUT:{}\n", output_lib_abs.to_string_lossy()));
        for a in &obj_rel_args {
            rsp.push_str(a);
            rsp.push('\n');
        }
        std::fs::write(&rsp_path, rsp)
            .with_context(|| format!("Failed to write response file {rsp_path:?}"))?;
    }

    // try lib.exe @archive.rsp
    {
        let args = [format!(
            "@{}",
            rsp_path.file_name().unwrap().to_string_lossy()
        )];
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run("lib.exe", &args_ref, &temp_dir_abs) {
            Ok((status, out, err)) => {
                tried.push(format!(
                    "lib.exe @archive.rsp\nstdout:\n{out}\nstderr:\n{err}"
                ));
                if status.success() {
                    archive_ok = true;
                }
            }
            Err(e) => {
                tried.push(format!("lib.exe failed to spawn: {e}"));
            }
        }
    }

    // try link.exe /lib @archive.rsp & llvm-lib.exe @archive.rs
    if !archive_ok {
        let rsp_name = rsp_path.file_name().unwrap().to_string_lossy().to_string();
        let arg_rsp = format!("@{rsp_name}");
        let args_ref: [&str; 2] = ["/lib", &arg_rsp];
        match run("link.exe", &args_ref, &temp_dir_abs) {
            Ok((status, out, err)) => {
                tried.push(format!(
                    "link.exe /lib @archive.rsp\nstdout:\n{out}\nstderr:\n{err}"
                ));
                if status.success() {
                    archive_ok = true;
                }
            }
            Err(e) => {
                tried.push(format!("link.exe failed to spawn: {e}"));
            }
        }
    }
    if !archive_ok {
        let arg0 = format!("@{}", rsp_path.file_name().unwrap().to_string_lossy());
        let args_ref: [&str; 1] = [arg0.as_str()];
        match run("llvm-lib.exe", &args_ref, &temp_dir_abs) {
            Ok((status, out, err)) => {
                tried.push(format!(
                    "llvm-lib.exe @archive.rsp\nstdout:\n{out}\nstderr:\n{err}"
                ));
                if status.success() {
                    archive_ok = true;
                }
            }
            Err(e) => {
                tried.push(format!("llvm-lib.exe failed to spawn: {e}"));
            }
        }
    }

    if !archive_ok {
        bail!(
            "Failed to create MSVC .lib at {:?}.\nTried:\n{}",
            output_lib_abs,
            tried.join("\n\n---\n\n")
        );
    }

    println!("-> Successfully created patched MSVC .lib at: {output_lib_abs:?}");
    println!("-> Intermediate patched .obj files are in: {temp_dir_abs:?}");

    Ok(())
}

fn patch_object_file(data: &[u8], symbols_to_rename: &[String], suffix: &str) -> Result<Vec<u8>> {
    let file = File::parse(data).context("Failed to parse object file")?;

    if file.format() != BinaryFormat::Coff || file.kind() != ObjectKind::Relocatable {
        bail!("Not a relocatable COFF file, skipping.");
    }

    let mut writer = Object::new(BinaryFormat::Coff, file.architecture(), Endianness::Little);

    // original section -> new section
    let mut section_map: HashMap<usize, SectionId> = HashMap::new();
    // original sym index -> new sym index
    let mut symbol_map: HashMap<usize, SymbolId> = HashMap::new();

    // copy sections
    let mut section_sym_map: HashMap<usize, SymbolId> = HashMap::new();

    for section in file.sections() {
        let name_bytes = match section.name_bytes() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        let name_vec = name_bytes.to_vec();
        let kind = section.kind();

        let new_section_id = writer.add_section(Vec::new(), name_vec.clone(), kind);

        let align = section.align();
        if kind != SectionKind::UninitializedData {
            let data_bytes = section
                .uncompressed_data()
                .context("Failed to get section data")?
                .into_owned();
            if !data_bytes.is_empty() {
                writer
                    .section_mut(new_section_id)
                    .set_data(data_bytes, align);
            }
        }

        let sec_sym = Symbol {
            name: name_vec.clone(),
            value: 0,
            size: 0,
            kind: SymbolKind::Section,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(new_section_id),
            flags: SymbolFlags::None,
        };
        let sec_sym_id = writer.add_symbol(sec_sym);

        section_map.insert(section.index().0, new_section_id);
        section_sym_map.insert(section.index().0, sec_sym_id);
    }

    for symbol in file.symbols() {
        let orig_idx = symbol.index().0;

        // if this input symbol is the section-defining symbol, map it directly to our created section symbol
        if symbol.kind() == SymbolKind::Section {
            if let object::SymbolSection::Section(sec_idx) = symbol.section() {
                if let Some(&sec_sym_id) = section_sym_map.get(&sec_idx.0) {
                    symbol_map.insert(orig_idx, sec_sym_id);
                    continue;
                } else {
                    continue;
                }
            } else {
                // section kind but not defined by a section?
                continue;
            }
        }

        let name_opt = symbol.name().ok();
        let mut name = name_opt.unwrap_or("").to_string();

        if !name.is_empty() && symbols_to_rename.iter().any(|s| s == &name) {
            name = format!("{name}_{suffix}");
        }

        // mangle __real, __xmm, ...
        if !name.is_empty() && (name.starts_with("__real") || name.starts_with("__xmm")) {
            name = format!("{name}_{suffix}");
        }

        let new_sym_section = match symbol.section() {
            object::SymbolSection::Undefined => SymbolSection::Undefined,
            object::SymbolSection::Absolute => SymbolSection::Absolute,
            object::SymbolSection::Common => SymbolSection::Common,
            object::SymbolSection::Section(idx) => {
                if let Some(&sid) = section_map.get(&idx.0) {
                    SymbolSection::Section(sid)
                } else {
                    SymbolSection::Undefined
                }
            }
            object::SymbolSection::Unknown => SymbolSection::Undefined,
            _ => SymbolSection::Undefined,
        };

        if name.is_empty() && matches!(new_sym_section, SymbolSection::Section(_)) {
            continue;
        }

        let wsym = Symbol {
            name: name.into_bytes(),
            value: symbol.address(),
            size: symbol.size(),
            kind: symbol.kind(),
            scope: symbol.scope(),
            weak: symbol.is_weak(),
            section: new_sym_section,
            flags: SymbolFlags::None,
        };

        let sid = writer.add_symbol(wsym);
        symbol_map.insert(orig_idx, sid);
    }

    // copy & update relocations
    for section in file.sections() {
        // skip unnamed/synthetic sections
        let Some(&new_section_id) = section_map.get(&section.index().0) else {
            continue;
        };

        for (offset, relocation) in section.relocations() {
            let (target_symbol, kind, encoding, size, addend) = match relocation.target() {
                RelocationTarget::Symbol(index) => {
                    if let Some(&sym) = symbol_map.get(&index.0) {
                        (
                            sym,
                            relocation.kind(),
                            relocation.encoding(),
                            relocation.size(),
                            relocation.addend(),
                        )
                    } else if let Some(&sec_sym) = section_sym_map.get(&index.0) {
                        (
                            sec_sym,
                            relocation.kind(),
                            relocation.encoding(),
                            relocation.size(),
                            relocation.addend(),
                        )
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            let flags = writeobj::RelocationFlags::Generic {
                kind,
                encoding,
                size,
            };

            let reloc = Relocation {
                offset,
                symbol: target_symbol,
                addend,
                flags,
            };
            writer
                .add_relocation(new_section_id, reloc)
                .context("Failed to add relocation to the new section")?;
        }
    }

    let result_bytes = writer
        .write()
        .context("Failed to write the new object file")?;
    Ok(result_bytes)
}
