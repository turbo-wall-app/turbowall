# TurboWall | WAF (Web Application Firewall) and Rate Limiter

Open-source WAF (Web Application Firewall) and rate limiter with unlimited rules, custom logic, and built-in protection against common web attacks. Deploy it on Cloudflare or any cloud provider, including Hetzner, DigitalOcean, and AWS. Get started in minutes without lengthy setup guides.

TurboWall is an open-source alternative to Cloudflare WAF and other proprietary WAF solutions.

TurboWall can be deployed:

* On Cloudflare Workers (the free plan is sufficient)
* On any cloud server (VPS, dedicated server, or on-premises infrastructure) with a public IP address *(coming soon)*

## TurboWall vs. Cloudflare WAF

* TurboWall allows you to create rules using all available request and response fields, including `http.request.body`, which is only available with Cloudflare WAF Enterprise plans.
* TurboWall makes it easy to add custom logic through JavaScript functions with access to all request and response data.
* TurboWall has no limits on the number of WAF or rate-limiting rules.
* TurboWall can be deployed on your own cloud infrastructure, dedicated servers, or on-premises environments.
* TurboWall includes more built-in rules.
* TurboWall can load-balance requests based on various parameters, including client location.
* TurboWall provides access to all features without requiring Enterprise agreements or unpredictable pricing.
* TurboWall can be managed as Infrastructure as Code (IaC), allowing you to store and version-control all rules in a Git repository.

## Using TurboWall with Cloudflare (Worker Version)

When deployed on Cloudflare, TurboWall runs as a Worker and handles all requests sent to the configured domains. You can think of it as a Cloudflare WAF and rate limiter with unlimited rules and fully customizable logic.

### Setup

1. Create a Cloudflare account if you don't already have one.
2. Add your domain to Cloudflare. All domains and subdomains protected by TurboWall must have Cloudflare proxy mode enabled.
3. Clone the repository.
4. Edit `src/config.json` and add your WAF rules.
5. Edit `wrangler.toml` in the project root and configure your domain.
6. Install Wrangler:

```bash
npm install -g wrangler
wrangler login
```

7. From the project root directory (where `wrangler.toml` is located), deploy TurboWall:

```bash
wrangler deploy
```

8. Verify that everything works by sending a request that should be blocked.
9. To update the rules, edit `config.json` and redeploy:

```bash
wrangler deploy
```

### Cloudflare Limitations

* Cloudflare adds headers such as `Server`, `CF-RAY`, `CF-Cache-Status`, and others when a domain is using proxy mode. These headers cannot be removed. To avoid them, deploy TurboWall on your own server and either disable Cloudflare proxy mode or use a different DNS provider.

* You should still secure your origin servers. If an attacker discovers your server's IP address, they can bypass Cloudflare and attack the server directly, including through DDoS attacks. Cloudflare does not provide a fixed set of source IP addresses dedicated to your account, so simply allowing a few IPs is not practical.

  To protect origin servers, deploy TurboWall on a cloud server (VPS, dedicated server, or on-premises infrastructure), disable public IP addresses on your origin servers, use private networking provided by your cloud provider, and allow traffic only from trusted private network addresses. This prevents direct access to your origin infrastructure from the public internet.

* Cloudflare Workers provides a generous free tier suitable for many projects. For applications handling more than approximately 100 uncached requests per second, a paid plan may be required. Even at that scale, Cloudflare Workers remains cost-effective for the amount of compute it provides. Refer to the Cloudflare Workers pricing page for details, and consider setting up budget alerts to avoid unexpected charges.

## Using TurboWall on Your Own Servers (Standalone Version)

The standalone version can be deployed on any server with a public IP address. We provide a ready-to-use deployment script for Ubuntu 24.04 LTS.

The standalone version helps you avoid potentially unpredictable costs associated with pay-as-you-go pricing models such as Cloudflare Workers. It also gives you full control over your traffic and data. When using Cloudflare Workers, Cloudflare decrypts your traffic and forwards it to your Worker. With the standalone version, only your infrastructure processes the traffic.

On the other hand, if you do not use Cloudflare's proxy mode, you lose Cloudflare's DDoS protection. However, many cloud providers already offer DDoS protection, including Hetzner.

### Deploying the Standalone Version

Work in progress...

### Synchronizing over an Overlay Network (Distributed SQLite)

TurboWall's standalone version supports reading WAF configurations and storing rate limits/request logs in a local SQLite database. By pairing this with tools like **Marmot** or **LiteFS**, you can easily distribute and synchronize state across multiple servers on a peer-to-peer overlay network, avoiding the need for heavy external databases like Redis.

To use the SQLite database integration:
1. In your Caddyfile, add the `db_path` parameter to the `custom_waf` directive:
```caddyfile
custom_waf {
    db_path /var/lib/turbowall/turbowall.db
}
```
2. TurboWall automatically creates the necessary `rules`, `rate_limits`, and `request_logs` tables.
3. Updates to the WAF rules in the database are hot-reloaded automatically every 5 seconds.

### Building the Standalone Version from Source

1. Install Go.
2. Clone the repository and change the directory to `src/turbowall-go`.
3. Install xcaddy and build TurboWall:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 xcaddy build --with turbowall-go=.
```

4. The executable file will be created in the current directory.
