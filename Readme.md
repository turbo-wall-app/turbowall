# TurboWall | WAF (Web Application Firewall) and Rate Limiter

Open-source WAF (Web Application Firewall) and rate limiter with unlimited rules, custom logic, and built-in protection against common web attacks. Deploy to Cloudflare or any cloud provider, including Hetzner, DigitalOcean, and AWS. Get started in minutes without lengthy setup guides. An open-source alternative to Cloudflare WAF and other proprietary WAF solutions.

TurboWall can be deployed:

* On Cloudflare Workers (the free plan is sufficient)
* On any cloud server (VPS, dedicated server, or on-premises infrastructure) with a public IP address *(coming soon)*

## TurboWall vs Cloudflare WAF

* TurboWall allows you to create rules using all available request and response fields (including `http.request.body`, which is only available with Cloudflare WAF Enterprise plans).
* TurboWall makes it easy to add custom logic through JavaScript functions that have access to all request and response data.
* TurboWall has no limits on the number of WAF or rate-limiting rules.
* TurboWall can be deployed on your own cloud infrastructure, dedicated servers, or on-premises environments.
* TurboWall includes more built-in rules.
* TurboWall can load balance requests based on various parameters, including client location.
* TurboWall provides access to all features without requiring Enterprise agreements and unpredictable pricing.
* TurboWall can be managed as Infrastructure as Code (IaC), allowing you to store and version-control all rules in a Git repository, for example.


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

* Cloudflare Workers provides a generous free tier that is suitable for many projects. For applications handling more than approximately 100 non-cached requests per second, a paid plan may be required. Even at that scale, Cloudflare Workers remains cost-effective for the amount of compute it provides. Refer to the Cloudflare Workers pricing page for details, and consider setting up budget alerts to avoid unexpected charges.


## How to Use with own servers

In progress ...
