# initzig

A container init that is so simple it's effectively brain-dead.
This is a rewrite of [catatonit](https://github.com/openSUSE/catatonit) in Zig.
By using Zig, initzig is not linked with libc; raw syscalls are used instead.
This results in smaller binary size and memory footprint.

## Usage

### Build

```console
$ zig build --release
```

### Install

```console
$ sudo install -Dsm755 zig-out/bin/initzig /usr/bin
```

### Use with Podman

Edit [`containers.conf`](https://man.archlinux.org/man/containers.conf.5.en):
```ini
[containers]
init_path="/usr/bin/initzig"
```
