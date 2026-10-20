# Host setup (Proxmox lab VM, later the Linode)

Target: Ubuntu Server 24.04 LTS. You need sudo.

## 1. Base packages and Docker

```bash
sudo apt update && sudo apt -y upgrade
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # log out and back in
```

## 2. Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --ssh            # or --login-server=https://<headscale> for Headscale
tailscale ip -4                    # -> TAILSCALE_IP in .env
```

Enable MagicDNS in the admin console if you want a name such as
`scanner.<tailnet>.ts.net` for `SITE_HOST`. Otherwise set `SITE_HOST` to the
Tailscale IP.

Restrict who can reach the node with a tailnet ACL, so only staff devices can
connect to `tag:scanner:443`.

## 3. Firewall (UFW)

Docker-published ports bypass UFW. The real control is Caddy binding only to
`$TAILSCALE_IP` (enforced by `tests/test_compose.py`). UFW still protects
everything else on the host:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on tailscale0
sudo ufw allow 41641/udp           # Tailscale direct connections (optional, improves latency)
sudo ufw enable
```

Once you have confirmed you can reach SSH over Tailscale, remove any public SSH
rule. Full lock-down is in M6.

## 4. Deploy the stack

```bash
git clone <repo> && cd scanner-platform
cp .env.example .env && chmod 600 .env
# Fill in .env. Generate each secret with:
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up -d --build
docker compose ps                  # api, postgres, valkey healthy; caddy up
./scripts/check-exposure.sh        # must print OK
docker compose exec api python -m app.cli create-user <your-name>
```

## 5. Trust Caddy's internal CA (once per staff device)

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

Install `caddy-root.crt` as a trusted root on each staff device (macOS Keychain,
Windows "Trusted Root Certification Authorities", Linux
`/usr/local/share/ca-certificates/` and then `update-ca-certificates`).

Alternative: use Tailscale HTTPS certificates. Enable HTTPS in the Tailscale
admin console, set `SITE_HOST` to the `*.ts.net` name, mount
`/var/run/tailscale/tailscaled.sock` read-only into the caddy container, and
remove `tls internal` from the Caddyfile. Caddy then fetches the certificate
from tailscaled, and no root needs installing.

## 6. Verify M1

- [ ] `https://$SITE_HOST/` redirects to the login page, from a tailnet device only
- [ ] Login works, logout works, and the 6th wrong password in a row is refused with "Too many failed attempts"
- [ ] From outside the tailnet, `nmap -Pn -p 443,5432,6379,8000 <public-ip>` shows them all closed or filtered
- [ ] `./scripts/check-exposure.sh` prints OK
- [ ] `docker compose restart` keeps users (Postgres volume) and logs everyone out only when Valkey data is wiped

## Operations

- Logs: `docker compose logs -f api caddy verifier`.
- Audit log: `/app/audit` in the UI. Logins, failed logins, user changes made
  with the command-line tool, and every client, authorisation and scope change
  are recorded there. Postgres refuses edits and deletes.
- Add the Linode's own public range (and any other ranges that must never be
  scanned) to `BLOCKLIST_EXTRA` in `.env`.
- Authorisation PDFs live in the `authorisations` Docker volume. Back it up
  together with Postgres (M6).
- Disable a staff account immediately: `docker compose exec api python -m app.cli disable-user <name>`.
  Their existing sessions stop working on the next request.
- Log everyone out: `docker compose exec valkey sh -c 'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "session:*" | xargs -r valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning del'`
