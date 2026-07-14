# Service files for mojo-virani

Service definitions for `mojo-virani`, the HTTP face of Virani (remote
fetching/searching of PCAPs, default port 8080).

```
rc/
├── systemd/   # Linux (systemd) unit file + sysusers helper
└── freebsd/   # FreeBSD rc.d script
```

Only the HTTP face needs a service; local `virani` use needs nothing
running. `make install` does not install these — copy them into place as
shown below.

Application configuration (sets, `allowed_subnets`, `apikey`, the cache
dir, ...) comes from `/usr/local/etc/virani.toml`; see
[docs/configuration.md](../docs/configuration.md). The service files only
carry the listen address and the process supervision.

Two things to arrange regardless of platform:

- The service user needs **read access to every set path** and **write
  access to the cache dir** (default `/var/cache/virani`; both service
  files create it owned by the service user at start).
- Mind what you listen on. Auth is by IP allow-list, optionally plus an API
  key — and behind a reverse proxy the allow-list sees the proxy's address,
  not the client's. Read [docs/security.md](../docs/security.md) before
  exposing it or fronting it with a proxy.

### One request at a time, or many

`mojo-virani daemon` (the default in both service files) handles one
request at a time — a long carve blocks other requests. To serve
concurrently, swap in Mojolicious' preforking server:

```
prefork -m production -w 4 -l http://*:8080
```

On systemd edit `ExecStart=`; on FreeBSD set it in `virani_flags`. Each
worker carves independently; identical queries still share the cache.

---

## Linux (systemd)

1. Install the unit and create the `virani` service user:

   ```sh
   install -m 0644 systemd/virani.service /etc/systemd/system/
   install -m 0644 systemd/virani.sysusers.conf /etc/sysusers.d/virani.conf
   systemd-sysusers
   ```

   (Or create the user by hand: `useradd --system --home-dir
   /var/cache/virani --shell /usr/sbin/nologin virani`.)

2. Grant the `virani` user read access to your set paths, e.g. by adding it
   to the group owning the FPC's output directory.

3. Set the listen URL if the default `http://*:8080` does not suit. Either
   edit `Environment=VIRANI_LISTEN=` in the unit, or drop an optional
   environment file (overrides the unit default):

   ```sh
   install -d /usr/local/etc/virani
   echo 'VIRANI_LISTEN=http://127.0.0.1:8080' > /usr/local/etc/virani/virani.env
   ```

4. Enable and start:

   ```sh
   systemctl daemon-reload
   systemctl enable --now virani.service
   systemctl status virani.service
   journalctl -u virani -f
   ```

### Notes

- **Paths.** `ExecStart=` references `/usr/local/bin/mojo-virani`; adjust if
  `make install` placed it elsewhere (e.g. `/usr/bin`).
- **Hardening.** The unit is sandboxed (`ProtectSystem=strict`, a
  `@system-service` syscall filter, etc.). Reading the sets works fine
  read-only, and the cache lives in the unit's `CacheDirectory`
  (`/var/cache/virani`) — but if `cache` in `virani.toml` points elsewhere,
  add a matching `ReadWritePaths=` line, and if your sets live under
  `/home`, drop `ProtectHome=`.
- **Binding a privileged port directly** (e.g. `:443`): set `VIRANI_LISTEN`
  accordingly and uncomment the `AmbientCapabilities` /
  `CapabilityBoundingSet` lines in the unit.

---

## FreeBSD (rc.d)

1. Install the rc.d script:

   ```sh
   install -m 0555 freebsd/virani /usr/local/etc/rc.d/
   ```

2. Enable and configure in `/etc/rc.conf` (knobs are documented at the top
   of the script):

   ```sh
   sysrc virani_enable="YES"
   sysrc virani_flags="daemon -m production -l http://127.0.0.1:8080 -l http://192.168.14.1:8080"
   # sysrc virani_user="www"
   # sysrc virani_cache="/var/cache/virani"
   ```

3. Start:

   ```sh
   service virani start
   service virani status
   ```

### Notes

- The service runs as `virani_user` (default `www`); a dedicated,
  unprivileged user with read access to the set paths is recommended.
  `daemon(8)` supervises mojo-virani, restarts it on exit (5 s delay), and
  routes its output to syslog — set `virani_output` to a file path to log
  there instead (older versions of this script always logged to
  `/var/log/virani/virani.out`).
- `virani_flags` is the full argument list handed to mojo-virani, which is
  where the listen addresses (and `daemon` vs `prefork`) go.

---

## Serving HTTPS directly

The service defaults to plain HTTP. Mojolicious can terminate TLS itself:
give it an `https://` listen URL with `cert` and `key` query parameters.

```
https://*:8443?cert=/usr/local/etc/virani/tls/server.crt&key=/usr/local/etc/virani/tls/server.key
```

- Requires **`IO::Socket::SSL`** (not a hard dependency of Virani; install
  it only if you terminate TLS in the app).
- `cert` and `key` are PEM files readable by the service user. Under
  systemd they must also be on a normal system path — `ProtectHome=` hides
  home directories from the sandbox.
- An `https://` URL with **no** `cert`/`key` makes Mojolicious fall back to
  a built-in self-signed certificate — local testing only, never production.
- **systemd** — set `VIRANI_LISTEN` in the unit or the environment file;
  systemd treats the whole value as one argument, so the `&` needs no
  escaping.
- **FreeBSD** — put the URL in `virani_flags` after `-l`, keeping the whole
  value inside the double quotes so the shell does not treat the `&` as an
  operator.

The `virani` CLI talks HTTPS to it via `-r https://...` (needs
`LWP::Protocol::https` on the client side).
