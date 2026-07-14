# Installation

## Dependencies

| CPAN module                             | FreeBSD pkg              | Debian pkg                     |
|-----------------------------------------|--------------------------|--------------------------------|
| File::Find::IncludesTimeRange (≥ 0.2.0) | (cpanm)                  | (cpanm)                        |
| File::Find::Rule                        | p5-File-Find-Rule        | libfile-find-rule-perl         |
| File::Slurp                             | p5-File-Slurp            | libfile-slurp-perl             |
| JSON                                    | p5-JSON                  | libjson-perl                   |
| LWP (LWP::UserAgent, HTTP::Request)     | p5-libwww                | libwww-perl                    |
| LWP::Protocol::https                    | p5-LWP-Protocol-https    | liblwp-protocol-https-perl     |
| Mojolicious                             | p5-Mojolicious           | libmojolicious-perl            |
| Net::Subnet                             | p5-Net-Subnet            | libnet-subnet-perl             |
| Parallel::ForkManager (≥ 2.02)          | p5-Parallel-ForkManager  | libparallel-forkmanager-perl   |
| TOML                                    | p5-TOML                  | libtoml-perl                   |
| Time::Piece::Guess (≥ 0.1.0)            | (cpanm)                  | (cpanm)                        |
| URI (URI::Escape)                       | p5-URI                   | liburi-perl                    |

Plus the core modules Digest::MD5, File::Copy, File::Path, File::Spec,
IPC::Cmd, Sys::Syslog, and Time::Piece. LWP::Protocol::https is only needed
for HTTPS remotes.

Package names are current as of writing. Anything marked `(cpanm)` — or
missing from your release — installs cleanly from CPAN via
[cpanminus](https://metacpan.org/pod/App::cpanminus).

## The external tools

The carving itself is done by external binaries on the `PATH` of whatever
runs the search (the box holding the PCAPs — the mojo-virani side, when
remote)...

- **tcpdump** — the `tcpdump` type. In the FreeBSD base system; `tcpdump`
  on Debian.
- **tshark** and **mergecap** — the `tshark`/`bpf2tshark` types, the hosts
  index, and all merging. The `wireshark-nox11` package on FreeBSD (or
  `wireshark`); `tshark` and `wireshark-common` on Debian.

mergecap is needed for every search type; tshark additionally for the tshark
types and `--update-pcap-hosts`.

## From CPAN

```shell
cpanm Virani
```

## From source

From a checkout or an unpacked release tarball...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

This installs the `virani` and `mojo-virani` scripts along with the modules.

## FreeBSD

```shell
pkg install p5-Mojolicious p5-TOML p5-Net-Subnet p5-JSON p5-File-Slurp \
    p5-File-Find-Rule p5-Parallel-ForkManager p5-libwww p5-LWP-Protocol-https \
    p5-URI p5-App-cpanminus wireshark-nox11
cpanm Virani
```

## Debian

```shell
apt-get install libmojolicious-perl libtoml-perl libnet-subnet-perl \
    libjson-perl libfile-slurp-perl libfile-find-rule-perl \
    libparallel-forkmanager-perl libwww-perl liblwp-protocol-https-perl \
    liburi-perl tcpdump tshark wireshark-common cpanminus build-essential
cpanm Virani
```

## First run

Write a config (see [configuration.md](configuration.md)) pointing a set at
wherever your FPC writes its PCAPs, then ask for something...

```shell
virani -s now-5m -e now port 53
```

The result lands in `out.pcap` (change with `-w`). Whoever runs `virani`
needs read access to the set's path and, for caching, write access to the
cache dir (default `/var/cache/virani`) — with an output file specified an
unusable cache dir is quietly bypassed rather than fatal.

## Running mojo-virani at boot

Only the HTTP face needs a service; local `virani` use needs nothing
running. `make install` does not install the service files, so copy them
into place yourself from `rc/` in the source tree — `rc/freebsd/` holds the
rc.d script, `rc/systemd/` the systemd unit; full walkthroughs for both live
in [rc/README.md](../rc/README.md).

### FreeBSD rc.d

The script runs mojo-virani under daemon(8) as the `virani_user` (default
`www`), logging to syslog and creating the cache and run dirs on start...

```shell
install -m 555 rc/freebsd/virani /usr/local/etc/rc.d/
sysrc virani_enable=YES
sysrc virani_flags="daemon -m production -l http://127.0.0.1:8080 -l http://192.168.14.1:8080"
service virani start
```

The rc.conf knobs are documented at the top of the script; the flags are
the arguments handed to mojo-virani, which is where the listen addresses
go. The user it runs as needs read access to every set path and write
access to the cache dir. Mind what you listen on; see
[security.md](security.md).

### Linux systemd

The unit runs mojo-virani as a dedicated `virani` user in a sandbox,
logging to the journal...

```shell
install -m 0644 rc/systemd/virani.service /etc/systemd/system/
install -m 0644 rc/systemd/virani.sysusers.conf /etc/sysusers.d/virani.conf
systemd-sysusers
systemctl daemon-reload
systemctl enable --now virani.service
```

Grant the `virani` user read access to the set paths, and set the listen
URL via `VIRANI_LISTEN` in the unit or in
`/usr/local/etc/virani/virani.env` — see [rc/README.md](../rc/README.md)
for the details.

### Elsewhere

`mojo-virani` is a stock Mojolicious::Lite app, so anything that can keep
one alive works...

```shell
mojo-virani daemon -m production -l http://127.0.0.1:8080
```

...under your supervisor of choice, or via hypnotoad, or copied into a CGI
bin, or as fastCGI with a frontend proxying to it. The one caution on
proxying: the IP allow-list sees the address of whoever connects, which
behind a proxy is the proxy — see [security.md](security.md) before fronting
it with one.
