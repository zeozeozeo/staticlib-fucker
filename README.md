# staticlib-fucker

A utility for mangling names in static object files. Mainly useful for leakage of non-exported symbols in Rust static libraries. (see https://github.com/rust-lang/rust/issues/104707).

This is to prevent collisions of exported symbols when linking multiple Rust static libraries[^1]:

```
wesl_c.lib(wesl_c.1ichu27y6kwsyom9vxw9s5df9.rcgu.o) : error LNK2005: __rust_no_alloc_shim_is_unstable already defined in wgpu_native.lib(wgpu_native.bxltiha8spj938iuaxui54rnl.rcgu.o)
wesl_c.lib(std-c85e9beb7923f636.std.df32d1bc89881d89-cgu.0.rcgu.o) : error LNK2005: rust_eh_personality already defined in wgpu_native.lib(std-41414eb11fafff20.std.f6fdcf5d182fc0b6-cgu.0.rcgu.o)
fatal error LNK1169: one or more multiply defined symbols found
```

(Rust shouldn't export these in the first place, but oh well.)

# Installation

```bash
cargo install staticlib-fucker
```

or grab one of the [Releases](https://github.com/zeozeozeo/staticlib-fucker/releases)

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

[^1]: https://alanwu.space/post/symbol-hygiene/
