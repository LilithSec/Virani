# Usage

## Asking locally

On the box holding the PCAPs, a search is a start, an end, and a filter...

```shell
# all port 53 traffic in a two minute window, written to out.pcap
virani -s 2026-07-13T11:00:18 -e 2026-07-13T11:02:18 port 53

# the last hour of traffic to or from one host, into a named file
virani -s now-1h -e now -w suspect.pcap host 192.168.14.42

# a different set and the tshark type for this one question
virani --set trunk -t tshark -s now-10m -e now 'ip.addr == 10.9.9.9'
```

The filter is whatever trails the switches (or `-f <filter>`), and the type
decides its dialect — BPF for `tcpdump` and `bpf2tshark`, a native display
filter for `tshark`. If `-f` names a file, the file is read as the filter,
with blank lines and `#` comments stripped and the rest joined into one
line — handy for long carefully-built filters.

An empty filter is allowed and matches everything: the PCAPs overlapping the
window are merged whole.

### Time formats

`-s` and `-e` take anything
[Time::Piece::Guess](https://metacpan.org/pod/Time::Piece::Guess) can make
sense of — ISO 8601 style stamps, epoch seconds, and the relative forms...

```
now       the current time
now-30    30 seconds ago
now-30m   30 minutes ago
now-30h   30 hours ago
now-30w   30 weeks ago
```

`--buffer <secs>` widens the asked window by that many seconds on each side,
on top of the configured `padding`.

### The switches

```
-s <ts>            start of the window
-e <ts>            end of the window
-f <filter>        the filter, or a file holding it; trailing args otherwise
-t <type>          tcpdump, tshark, or bpf2tshark
--set <set>        which set; the default set otherwise
-w <file>          where to write the PCAP... default out.pcap
--nc               ignore a cached answer, regenerate
--buffer <secs>    widen the window by this much on each side
--config <file>    config to use... default /usr/local/etc/virani.toml
-q                 hush the narration

--list-sets        print the configured sets and the default set as JSON
--list-cached      print the cached searches as JSON... --set to limit
--cached <id>      fetch a cached answer by ID... --meta for JSON only
--update-pcap-hosts  refresh the hosts index for a set... local only

-r <remote>        ask a remote mojo-virani instead... URL or virani.d name
-a <apikey>        API key for the remote
-k                 skip HTTPS cert verification
--timeout <secs>   remote fetch timeout
```

Every search writes the PCAP to `-w` and leaves the full accounting in the
cache metadata; `--list-cached` and `--cached` read them back later — see
[cache.md](cache.md).

## Asking remotely

`-r` turns the same CLI into a client of a remote mojo-virani. It takes a
URL directly or the name of a config under `virani.d/` (see
[configuration.md](configuration.md))...

```shell
virani -r https://sensor1.example.com:8080/ -s now-1h -e now port 53
virani -r sensor1 -s now-1h -e now port 53
virani -r sensor1 --list-sets
virani -r sensor1 --list-cached
virani -r sensor1 --cached wan-tcpdump-1752400000-1752403600-9a0364b9e99bb480dd25e1f0284c8555
```

The window is parsed locally and sent as epoch seconds, so the relative
`now-*` forms work against any server. The search runs on the far side —
its config, its sets, its cache — and the PCAP plus metadata JSON come back
over the wire. `--update-pcap-hosts` is the one local-only verb, as the
index belongs to the box holding the PCAPs.

The API key resolves as `-a`, then `$ENV{virani_api_key}`, then the
`virani.d` file; the timeout as `--timeout`, then `$ENV{virani_timeout}`,
then the file. For HTTPS, `-k` disables cert verification.

## The HTTP parameters

mojo-virani answers GET on any path, driven entirely by query parameters.
Every request passes the IP allow-list (and the API key, when
`auth_by_IP_only` is false) first — see [security.md](security.md).

| parameter       | what                                                             |
|-----------------|-------------------------------------------------------------------|
| `start` / `stime` | start of the window... anything Time::Piece::Guess parses       |
| `end` / `etime`   | end of the window                                               |
| `bpf`           | the filter. Required for a search and may not be empty.          |
| `set`           | which set; the server's default set otherwise                    |
| `type`          | `tcpdump`, `tshark`, or `bpf2tshark`                              |
| `apikey`        | the API key, when the server checks one                          |
| `get_meta=1`    | return the metadata JSON for the search instead of the PCAP      |
| `get_sets=1`    | return the configured sets and default set as JSON               |
| `list_cached=1` | return the cached searches as JSON... combinable with `set`      |
| `cached=<id>`   | return a cached answer by ID... with `get_meta=1`, its JSON      |

A search generates (or pulls from cache) and returns the PCAP as
`application/x-download`. `get_meta=1` on the same URL then returns its
metadata JSON — the PCAP fetch first, then the metadata, is exactly what
`Virani::Client` does. Note the server does not honor the relative `now-*`
forms; send epochs or full stamps.

```shell
curl -o out.pcap 'http://sensor1:8080/?start=1752400000&end=1752403600&bpf=port%2053'
curl 'http://sensor1:8080/?start=1752400000&end=1752403600&bpf=port%2053&get_meta=1'
curl 'http://sensor1:8080/?get_sets=1'
curl 'http://sensor1:8080/?list_cached=1&set=wan'
```

Failures come back as `403` (key or IP refused), `400` (missing or
unparsable parameters, end before start, bad type, empty filter, or every
PCAP failing to process), `404` (unknown cache ID), and `418` (PCAP
generation died server side — details land in the server's syslog).

## From Perl

The same two halves are usable directly...

```perl
use Virani;
use Time::Piece::Guess;

my $virani = Virani->new_from_conf( conf => '/usr/local/etc/virani.toml' );
my $meta   = $virani->get_pcap_local(
    start  => Time::Piece::Guess->guess_to_object('now-1h', 1),
    end    => Time::Piece::Guess->guess_to_object('now', 1),
    filter => 'port 53',
    file   => 'out.pcap',
);
print 'kept ' . $meta->{final_size} . " bytes from " . $meta->{pcap_count} . " PCAPs\n";
```

```perl
use Virani::Client;

my $vc = Virani::Client->new( url => 'https://sensor1.example.com:8080/' );
$vc->fetch( start => $start_tp, end => $end_tp, filter => 'port 53', file => 'out.pcap' );
```

`perldoc Virani` and `perldoc Virani::Client` carry the full reference,
including every key of the returned metadata.
