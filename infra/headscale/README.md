# Headscale dev instance

A local instance of [Headscale](https://github.com/juanfont/headscale) for
tailscale-vita development. Headscale implements the same coordination
protocol as Tailscale's hosted control plane, so the Vita client can
develop against this and we get full visibility into every wire byte
(`docker compose logs -f headscale`, `tcpdump`, etc.).

## Bring it up

```bash
cd infra/headscale

# First time only: create your local config from the template and
# edit `server_url:` to point at the dev host's LAN IP (or hostname).
cp config/config.yaml.example config/config.yaml
$EDITOR config/config.yaml

docker compose up -d
docker compose logs -f headscale     # tail logs

# Create a user and a long-lived auth key for the Vita.
docker compose exec headscale headscale users create vita
docker compose exec headscale headscale preauthkeys create -e 720h --user vita
# Copy the printed `tskey-auth-...` value — that's the auth key the
# Vita client will use to register itself.
```

## Sanity check with a known-good client

Before pointing the Vita client at this server, verify Headscale itself
works using a regular `tailscale` binary on your laptop or a
container:

```bash
# On your laptop:
tailscale up \
  --login-server=http://<your-host>:8080 \
  --auth-key=tskey-auth-XXXXXXXX
tailscale status
docker compose exec headscale headscale nodes list
```

If the laptop appears in `nodes list` and the laptop's `tailscale status`
shows itself online, the control plane is fully working and ready for
Vita-client development.

## Files

- `docker-compose.yml` — the Headscale container.
- `config/config.yaml.example` — Headscale config template (upstream
  example with placeholders for local dev). Copy to `config/config.yaml`
  and edit `server_url` to match your LAN IP/hostname so the Vita can
  reach it. The live `config/config.yaml` is `.gitignore`d so your
  network details stay out of the repo.
- `lib/` — Headscale's persistent state (SQLite DB + node keys).
  Created automatically on first run; `.gitignore`d.

## Network topology for Phase 1+ work

```
Vita (real or Vita3K)
   |  Wi-Fi (or Vita3K NAT through host)
   |  HTTPS to control plane
   v
Headscale @ http://<dev-host>:8080
   |
   v
SQLite at lib/db.sqlite
```

For DERP relay (phase 4 of the master plan), Headscale ships a default
DERP map pointing at Tailscale's relays. Override with
`derp.urls`/`derp.paths` in `config.yaml` if you want to test a local
DERP server.
