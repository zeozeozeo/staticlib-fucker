# staticlib-fucker

A utility for mangling names in static object files. Mainly useful for leakage of non-exported symbols in Rust static libraries. (see https://github.com/rust-lang/rust/issues/104707)

# Usage

```bash
staticlib-fucker --input mylib.lib --output mylib_mangled.lib
```

This will mangle `rust_eh_personality` and `__rust_no_alloc_shim_is_unstable` by default.

If you want to provide a specific list of symbols to mangle:

```bash
staticlib-fucker --input mylib.lib --output mylib_mangled.lib --symbols mysym_1,mysym_2,mysym_3
```

use `--help` or `-h` for help:

```
A utility for mangling names in static object files. Mainly useful for leakage of non-exported symbols in Rust static libraries. (see https://github.com/rust-lang/rust/issues/104707)

Usage: staticlib-fucker.exe [OPTIONS] --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>
  -o, --output <OUTPUT>
      --symbols <SYMBOLS>  [default: __rust_no_alloc_shim_is_unstable,rust_eh_personality]
  -h, --help               Print help
  -V, --version            Print version
```
