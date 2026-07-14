# Configuration

The config file is TOML, by default `/usr/local/etc/virani.toml` (overridable
with `virani --config <path>`; mojo-virani always reads the default path).
Top level keys are global settings and defaults; each hash under `sets`
defines one PCAP hoard to read, named for the hash — the hash at
`sets.default` is the set `default`.

## Global settings

| key                  | default                                                    | what                                                              |
|----------------------|------------------------------------------------------------|-------------------------------------------------------------------|
| `default_set`        | `"default"`                                                | the set used when a request names none                            |
| `cache`              | `/var/cache/virani`                                        | where answers and the hosts index are kept — see [cache.md](cache.md) |
| `allowed_subnets`    | `["192.168.0.0/16", "127.0.0.1/8", "::1/127", "172.16.0.0/12"]` | subnets allowed to talk to mojo-virani                       |
| `auth_by_IP_only`    | `true`                                                     | if true, mojo-virani never checks the API key                    |
| `apikey`             | (none)                                                     | the API key mojo-virani requires when `auth_by_IP_only` is false |
| `type`               | `"tcpdump"`                                                | default filter type... `tcpdump`, `tshark`, or `bpf2tshark`       |
| `padding`            | `5`                                                        | seconds added on either side of the window before finding PCAPs  |
| `workers`            | `4`                                                        | how many PCAPs to filter (or index) in parallel; 0 for one at a time |
| `default_regex`      | `(?<timestamp>\d\d\d\d\d\d+)(\.pcap\|(?<subsec>\.\d+)\.pcap)$` | the timestamp regex for sets that carry none                 |
| `ts_is_unixtime`     | `true`                                                     | the captured timestamp is epoch seconds as-is                    |
| `pcap_glob`          | `"*.pcap*"`                                                | the filename glob PCAPs must match                               |
| `pcap_hosts_min_age` | `120`                                                      | seconds a PCAP must sit unmodified before the hosts index will take it |
| `host_pruning`       | `false`                                                    | use the hosts index to skip PCAPs that can not match — see [host-pruning.md](host-pruning.md) |
| `verbose`            | `true`                                                     | narrate what is being done                                       |
| `verbose_to_syslog`  | `false`                                                    | narrate to syslog instead of stdout (mojo-virani turns this on itself) |

`allowed_subnets`, `auth_by_IP_only`, and `apikey` only matter for
mojo-virani; local `virani` use never consults them. See
[security.md](security.md) for how the gate works.

## Set settings

Inside a `[sets.<name>]` hash, only `path` is required. Everything else,
when present, overrides its global counterpart for that set...

| key                  | what                                                            |
|----------------------|-----------------------------------------------------------------|
| `path`               | the directory the PCAPs live under, searched recursively. Required. |
| `regex`              | the timestamp regex for this set's filenames                   |
| `type`               | default filter type for this set                                |
| `padding`            | padding seconds for this set                                    |
| `workers`            | worker count for this set                                       |
| `ts_is_unixtime`     | as the global                                                   |
| `pcap_glob`          | as the global                                                   |
| `pcap_hosts_min_age` | as the global                                                   |
| `host_pruning`       | as the global                                                   |

Resolution is always...

    per-request  >  per-set  >  global  >  built-in default

## The timestamp regex

Virani time-ranges a search off the epoch stamp in each PCAP's **filename**
— nothing is opened until the window has already narrowed the candidates.
The regex does that extraction, via named captures...

- `timestamp` — required. Must capture the epoch seconds in the name.
- `subsec` — optional. Captures a fractional-seconds part, dot included,
  for FPCs that stamp one in.

The default matches names ending in `<epoch>.pcap` or `<epoch>.<subsec>.pcap`
— the daemonlogger shape. A Lamashtu `rotate = "secs"` set names files
`<set>.pcap-<epoch>` instead, so it wants...

```toml
regex = '\.pcap-(?<timestamp>\d+)$'
```

`ts_is_unixtime` should stay true: the timestamp capture is epoch seconds
and is compared as such. (Setting it false routes the same value through
Time::Piece as `%s`, which lands in the same place more slowly.)

A file with no timestamp in its name can not be placed in time and will not
be searchable, so point sets only at hoards whose rotation stamps the epoch
in — on the Lamashtu side that means `rotate = "secs"` or `"both"`, not
`"size"`.

## A complete example

```toml
default_set     = "wan"
cache           = "/var/cache/virani"
allowed_subnets = ["192.168.14.0/23", "127.0.0.1/8"]
padding         = 5
workers         = 4

# daemonlogger writing to /var/log/daemonlogger... the default regex fits
[sets.default]
path = "/var/log/daemonlogger"

# what Lamashtu's "wan" set hoards
[sets.wan]
path  = "/var/log/lamashtu/pcap/wan"
regex = '\.pcap-(?<timestamp>\d+)$'

# a trunk port where tcpdump's BPF misses the VLAN'd traffic
[sets.trunk]
path    = "/var/log/lamashtu/pcap/trunk"
regex   = '\.pcap-(?<timestamp>\d+)$'
type    = "bpf2tshark"
workers = 2
```

Both faces read the config per use — the CLI at startup, mojo-virani per
request — so edits take effect on the next search, no restart needed.

## Remote configs... virani.d

`virani -r <remote>` takes either an HTTP(S) URL outright or the name of a
small TOML file describing a remote mojo-virani. Names are searched as...

    <remote>
    <remote>.toml
    /usr/local/etc/virani.d/<remote>
    /usr/local/etc/virani.d/<remote>.toml
    /etc/virani.d/<remote>
    /etc/virani.d/<remote>.toml

The keys of such a file...

| key       | what                                            |
|-----------|--------------------------------------------------|
| `url`     | the mojo-virani URL. Required.                   |
| `apikey`  | API key to send, if the far side wants one       |
| `timeout` | fetch timeout in seconds                         |

So `/usr/local/etc/virani.d/sensor1.toml` holding...

```toml
url    = "https://sensor1.example.com:8080/"
apikey = "wouldnotyouliketoknow"
```

...makes `virani -r sensor1 -s now-1h -e now port 53` work from anywhere
that can reach it. The API key can also come from `-a` or
`$ENV{virani_api_key}`, and the timeout from `--timeout` or
`$ENV{virani_timeout}` — CLI flag, then environment, then the file.
