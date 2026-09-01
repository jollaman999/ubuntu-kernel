# jollaman999 ubuntu-kernel

[한국어 문서](docs/README.ko.md)

The Ubuntu 26.10 (stonking) kernel with **arp_project** on top.

| | |
|---|---|
| Base | Ubuntu `linux 7.2.0-5.5` (stonking-proposed), upstream `v7.2` |
| upstream stable | `7.2.1` and `7.2.2` applied commit by commit |
| Package version | `7.2.2-5.5`, so `uname -r` says `7.2.2-5-generic` |
| Added | arp_project 2.5 |

## arp_project

It keeps the default gateway from being moved to somebody else's hardware
address. The gateway address is pinned down, and any attempt to move it is
accepted only after a unicast ARP probe has told a real attack apart from a
legitimate replacement.

The knobs live in `/sys/kernel/arp_project/`. `cat how_to_use` prints the
manual; `how_to_use_ko` is the Korean one.

A gateway that does not answer from a single hardware address (an HA pair, a
bonded link) is handled by `allow_multi_gw_hwaddr`. At the default `1`, a
second address that answers a unicast probe sent to it is accepted as another
port of the same gateway; at `0`, that second answer is treated as an attack
and blocked.

Full documentation:

- `Documentation/networking/arp_project.rst`
- `Documentation/translations/ko_KR/networking/arp_project.rst`

## How this differs from the stock Ubuntu kernel

### No zfs

Ubuntu makes `linux-modules` `Depends` on `linux-main-modules-zfs-<version>`.
That package is built **from a separate source package, and only against the
Ubuntu ABI**, so no build of it exists for the kernel built here (`7.2.2-5`).

Leaving the dependency in place makes `dpkg` refuse to configure
`linux-modules`, and that state sticks around and **stops apt from touching
any other package.** So it was dropped.

Ubuntu has a reason for making this a `Depends` rather than a `Recommends`.
The installer offers root-on-ZFS, and such a system will not boot at all if
the kernel has no `zfs.ko`. The dependency guarantees that a zfs root comes up
under whichever `linux-modules` you install.

This source package cannot produce that. `linux-main-modules-zfs` comes out of
the signed source (`linux-main-signed`), this tree's `all_dkms_modules` is
empty, and no zfs source is in here.

**If you need zfs, use `zfs-dkms`.** It builds against any kernel whose
headers are installed.

```sh
sudo apt install zfs-dkms linux-headers-7.2.2-5-generic
dkms status | grep zfs
```

**If your root is zfs, do that and check `dkms status` before you reboot into
this kernel.** Rebooting without checking gets you a system that does not
boot.

### ccache is used automatically

If `ccache` is installed, it wraps `CC`. Turn it off with `USE_CCACHE=0`, or
point at another binary with `CCACHE=<path>`. With no ccache installed,
nothing changes.

`HOSTCC` is not wrapped, because it is passed to rustc as
`-Clinker=$(HOSTCC)` and rustc takes only the first word as the linker.

## Building

Building anywhere other than Ubuntu 26.10 is easier in a container. You need
gcc 15, rustc 1.95, clang 21 and pahole 1.29 or newer.

```sh
fakeroot debian/rules clean
env rustc=/usr/bin/rustc-1.95 do_tools=false skipabi=true skipmodule=true \
    skipdbg=true skipretpoline=true DEB_BUILD_OPTIONS=parallel=$(nproc) \
    fakeroot debian/rules binary-generic
env rustc=/usr/bin/rustc-1.95 do_tools=false skipabi=true skipmodule=true \
    skipdbg=true skipretpoline=true \
    fakeroot debian/rules binary-indep
```

`rustc=` is given because `debian.master/config/annotations` requires
`CONFIG_RUSTC_VERSION=109500`. A default `rustc` older than that stops the
config check.

`binary-indep` builds the architecture-independent header package. DKMS needs
it.

## Installing

```sh
sudo dpkg -i linux-modules-7.2.2-5-generic_*.deb \
             linux-image-unsigned-7.2.2-5-generic_*.deb \
             linux-headers-7.2.2-5_*.deb \
             linux-headers-7.2.2-5-generic_*.deb
```

With Secure Boot on, `linux-image-unsigned` will not boot.

### Secure Boot

This tree does not produce a signed build. Stock Ubuntu's signed kernel
(`linux-image-7.2.2-5-generic`) is made by a separate source (`linux-signed`)
that comes out of Canonical's signing service, so a kernel built here cannot
be shipped that way. To run with Secure Boot on, you have two choices.

- **Sign it yourself (MOK).** Make a key once, enrol it in the firmware, and
  sign the installed kernel image. You need `mokutil` and `sbsigntool`.

  ```sh
  openssl req -new -x509 -newkey rsa:2048 -keyout MOK.key -out MOK.crt \
      -nodes -days 36500 -subj "/CN=local kernel/"
  openssl x509 -in MOK.crt -outform DER -out MOK.der

  sudo mokutil --import MOK.der   # pick a password. On reboot the MOK
                                  # manager comes up to confirm the enrolment

  sudo sbsign --key MOK.key --cert MOK.crt \
      --output /boot/vmlinuz-7.2.2-5-generic /boot/vmlinuz-7.2.2-5-generic
  ```

  Every newly installed kernel image has to be signed again.

- **Turn Secure Boot off.** With it off in the firmware, the unsigned image
  boots as it is.
