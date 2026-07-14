# Architecture

## The shape of it

```
              /usr/local/etc/virani.toml
                           |
                           v
   virani(1) ---------> Virani.pm <--------- mojo-virani
   the CLI              the library          HTTP, via Mojolicious::Lite
      |                    |    |                 ^
      | -r remote          |    |                 |
      v                    |    |            Virani::Client
   Virani::Client ---------|----|------> HTTP(S) |
                           |    |                |
                           v    v
        [sets.<name>].path      /var/cache/virani
        the PCAP hoard(s),      cached answers + metadata JSON
        read only               + the pcap_hosts index
```

Unlike her siblings there is no daemon of her own and no socket — Virani is a
**library** with two faces. Everything lives in `Virani.pm`; the faces just
carry questions to it...

- **`virani`** — the CLI. Ran locally it loads the config and searches the
  PCAP directories directly. Ran with `-r` it becomes a client instead,
  asking a remote mojo-virani over HTTP(S) via `Virani::Client`.
- **`mojo-virani`** — a Mojolicious::Lite app serving the same searches over
  HTTP. Runnable as a daemon (`mojo-virani daemon -m production -l
  http://<ip>:<port>`), as a CGI script, or as fastCGI. Gated by
  `allowed_subnets` and optionally an API key — see
  [security](security.md).

The two ends meet only at HTTP; the wire protocol is just query parameters
and a PCAP (or JSON) coming back. Anything that can speak HTTP can ask — see
[usage](usage.md) for the parameters.

## Sets

A set is one PCAP hoard: a directory some full packet capture writes into,
named by a `[sets.<name>]` hash in the config. Virani never writes there —
she is the reader, not the keeper. Each set carries its own timestamp regex,
filter type, padding, and worker count where they differ from the global
ones; see [configuration](configuration.md).

The one hard requirement on a set is that the PCAP **filenames carry the
epoch time**, because that is how Virani time-ranges her search without
opening every file. A Lamashtu set with `rotate = "secs"`, a daemonlogger
with `-t`, a Suricata or netsniff-ng ring — anything stamping `%s` into the
name works.

## From a window to a capture

Inside `get_pcap_local`, a question runs the gauntlet...

1. **Resolve.** The set, type, padding, and workers are settled — per set
   value if present, else the global, else the default. The filter is
   whitespace-normalized (so equivalent filters cache as one) and refused if
   it starts with a `-`.
2. **The cache check.** The answer's cache name is derived from set, type,
   the unpadded start and end epochs, and the MD5 of the cleaned filter. If
   both the PCAP and its metadata JSON already sit in the cache, that answer
   is returned as-is — hardlinked (or copied) to the output file if one was
   asked for. See [cache](cache.md).
3. **Pad.** `padding` seconds (default 5) are subtracted from the start and
   added to the end, so a packet right on the edge is not lost to rotation
   timing.
4. **Find.** The set's directory is walked recursively for files matching
   `pcap_glob` (default `*.pcap*`), and
   [File::Find::IncludesTimeRange](https://metacpan.org/pod/File::Find::IncludesTimeRange)
   narrows those to the ones whose filename timestamps overlap the padded
   window — including the file that began before the window and was still
   being written when it opened.
5. **Prune.** With `host_pruning` on and a filter that requires specific IP
   hosts, PCAPs whose indexed host lists rule out a match are dropped before
   any real work is spent on them. Unindexed PCAPs are always kept. See
   [host-pruning](host-pruning.md).
6. **Filter.** Each surviving PCAP is run through `tcpdump -r <pcap> -w
   <tmp> <filter>` (or tshark, per the type) into its own tmp file,
   `workers` of them in parallel via Parallel::ForkManager. A PCAP that
   fails — say the one still being written to — is recorded in `failed` and
   skipped, not fatal. An **empty filter** skips this stage entirely and
   merges the originals directly, falling back to per PCAP filtering if that
   merge fails.
7. **Merge.** The tmp files are merged into the final PCAP with `mergecap`
   (a single one is just moved into place, as tcpdump/tshark already
   validated it). The metadata JSON — sizes, counts, failures, timings, the
   filter, the cache ID — is written alongside it, and the result hardlinked
   or copied to the output file if one was named.

The required binaries are checked for up front, so a box missing tshark or
mergecap fails with a clear error rather than a pile of per PCAP failures.

## The filter types

- **tcpdump** — the filter is BPF, applied via tcpdump. The fast path and
  the default.
- **tshark** — the filter is a native tshark display filter. Significantly
  slower, but tshark dissects encapsulations tcpdump's BPF engine will not
  nicely handle, some VLAN arrangements being the classic case.
- **bpf2tshark** — write BPF, run tshark: the filter is translated to a
  display filter via a quick and dumb converter (`Virani->bpf2tshark`...
  `port 53` becomes `( tcp.port == 53 or udp.port == 53 )` and so on). BPF
  ergonomics with tshark's dissection; see the POD for what survives
  translation.

The type is pickable per request, per set, and globally, in that order of
precedence.

## What lives where

| path                                  | what                                                 |
|---------------------------------------|------------------------------------------------------|
| `/usr/local/etc/virani.toml`          | the config                                           |
| `/usr/local/etc/virani.d/<name>.toml` | remote definitions for `virani -r <name>`            |
| `[sets.<name>].path`                  | a set's hoard — someone else's to write, hers to read |
| `/var/cache/virani/`                  | cached answers... `<set>-<type>-<start>-<end>-<md5>` plus `.json` |
| `/var/cache/virani/pcap_hosts/<set>/` | the hosts index, one file per indexed PCAP           |

When verbosity is on, the CLI narrates to stdout and mojo-virani to syslog
(facility daemon, as `virani`).

## Where Virani sits in the pantheon

The household divides the work of one network...

- **[Baphomet](https://github.com/LilithSec/Baphomet)** reads the logs and
  *accuses*: repeat offenders are consigned to Ereshkigal.
- **[Ereshkigal](https://github.com/LilithSec/Ereshkigal)** rules Kur and
  *punishes*: it works the firewalls and holds the banned.
- **[Lamashtu](https://github.com/LilithSec/Lamashtu)** *remembers*: she
  seizes the packets and hoards them, so the traffic behind any event is
  already on disk.
- **[Lilith](https://github.com/LilithSec/Lilith)** *knows*: the alerts the
  watchers raise are gathered into her annals.
- **Virani** *reads*: when the packets behind a moment are wanted, she is
  the one sent into the hoard to fetch them.

Lamashtu and Virani are wired only by the PCAPs on disk — Lamashtu never
calls Virani and Virani never calls her; a Virani set simply points at the
directory a Lamashtu set fills. Lilith's packet fetching is a call to
mojo-virani. And none of it is exclusive to the household: any FPC that
writes timestamped PCAP files is a hoard Virani can read.

## The bits and pieces

| piece            | what                                                                    |
|------------------|-------------------------------------------------------------------------|
| `Virani`         | the library: config, set resolution, the search/filter/merge pipeline, the cache, the hosts index, bpf2tshark |
| `Virani::Client` | a small LWP HTTP(S) client for mojo-virani, used by `virani -r`         |
| `virani`         | the CLI, local and remote                                               |
| `mojo-virani`    | the Mojolicious::Lite HTTP face                                         |
| `rc/`            | service files for running mojo-virani at boot — FreeBSD rc.d and systemd |
