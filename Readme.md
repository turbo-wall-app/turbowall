# TurboWall | WAF (Web Application Firewall) and Rate Limiter

Open-source WAF (Web Application Firewall) and rate limiter with unlimited rules, custom logic, and built-in protection against common web attacks. Deploy to Cloudflare or any cloud provider, including Hetzner, DigitalOcean, and AWS. Get started in minutes without lengthy setup guides. An open-source alternative to Cloudflare WAF and other proprietary WAF solutions.

TurboWall can be deployed:

* On Cloudflare Workers (the free plan is sufficient)
* On any cloud server (VPS, dedicated server, or on-premises infrastructure) with a public IP address *(coming soon)*

## How to Use with Cloudflare

When deployed on Cloudflare, TurboWall runs as a Worker and handles all requests sent to the configured domains. You can think of it as a Cloudflare WAF and rate limiter with unlimited rules and fully customizable logic.

### Setup

- Create a Cloudflare account if you don't already have one.
- Add your domain to Cloudflare. All domains and subdomains protected by TurboWall must have Cloudflare proxy mode enabled.
- Clone the repository.
- Edit `config.json` and add your WAF rules.
- Edit `wrangler.toml` in the project root and configure your domain.
- Install Wrangler:

```bash
npm install -g wrangler
wrangler login
```

- From the project root directory (where `wrangler.toml` is located), deploy TurboWall:

```bash
wrangler deploy
```

- Verify that everything works by sending a request that should be blocked.
- To update the rules, edit `config.json` and redeploy:

```bash
wrangler deploy
```

## Cloudflare Limitations

* Cloudflare adds headers such as `Server`, `CF-RAY`, `CF-Cache-Status`, and others when a domain is using proxy mode. These headers cannot be removed. To avoid them, deploy TurboWall on your own server and either disable Cloudflare proxy mode or use a different DNS provider.

* You should still secure your origin servers. If an attacker discovers your server's IP address, they can bypass Cloudflare and attack the server directly, including through DDoS attacks. Cloudflare does not provide a fixed set of source IP addresses dedicated to your account, so simply allowing a few IPs is not practical.

  To protect origin servers, deploy TurboWall on a cloud server (VPS, dedicated server, or on-premises infrastructure), disable public IP addresses on your origin servers, use private networking provided by your cloud provider, and allow traffic only from trusted private network addresses. This prevents direct access to your origin infrastructure from the public internet.


## How to Use with own servers

In progress ...
