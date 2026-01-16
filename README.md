# nginx-waf

A dynamic nginx module for IP/CIDR-based access control with named lists and tag-based organization.

## ⚠️ Experimental Project

```
╔══════════════════════════════════════════════════════════════════╗
║  🧪 THIS PROJECT IS EXPERIMENTAL - NOT PRODUCTION READY         ║
║                                                                  ║
║  • Early development stage                                       ║
║  • API and features may change                                   ║
║  • Use at your own risk                                          ║
║  • Contributions and ideas welcome!                              ║
╚══════════════════════════════════════════════════════════════════╝
```

📅 **Started:** December 2025  
🎯 **Target:** v1.0.0 stable release  
📊 **Current:** v0.2.1 - Core Complete, Testing Phase

---

## What is nginx-waf?

**nginx-waf** is a simple, focused nginx module that provides IP-based access control. Think of it as a flexible IP blocklist/allowlist manager.

### Core Features

| Feature | Description |
|---------|-------------|
| 🏷️ **Named Lists** | Define lists with meaningful names (`tor`, `botnets`, `trusted`) |
| 🔖 **Tag Organization** | Group lists with tags for bulk management (`tag:anonymizers`) |
| ⚫ **Blacklist Mode** | Block IPs that match any active list |
| ⚪ **Whitelist Mode** | Allow only IPs that match active lists |
| 🎯 **Flexible Scope** | Configure at http, server, or location level |
| 🌐 **IPv4 & IPv6** | Full support with CIDR ranges |

### What nginx-waf is NOT

- ❌ **Not a full WAF** - No request body inspection, SQL injection detection, etc.
- ❌ **Not a rate limiter** - Use nginx's `limit_req` module
- ❌ **Not a bot detector** - IP lists only, no behavior analysis
- ❌ **Not a CDN** - Just access control

### Why Another Module?

- **Simpler than ModSecurity** - Focused on IP-based control only
- **Works with vanilla nginx** - No OpenResty required
- **Named lists with tags** - Organize dozens of lists easily
- **Per-location configuration** - Fine-grained control

---

## Quick Example

```nginx
http {
    # Define IP lists with tags
    waf_list tor "/etc/nginx/waf/tor-exits.txt" "anonymizers,privacy";
    waf_list botnets "/etc/nginx/waf/botnets.txt" "security";
    waf_list trusted "/etc/nginx/waf/trusted.txt" "internal";

    server {
        server_name api.example.com;

        # Block all anonymizers by default
        waf on;
        waf_mode blacklist;
        waf_enable_lists tag:anonymizers;

        location /admin {
            # Strict whitelist for admin
            waf on;
            waf_mode whitelist;
            waf_enable_lists trusted;
        }

        location /public {
            # No restrictions on public endpoints
            waf off;
        }
    }
}
```

---

## Configuration Reference

| Directive | Context | Arguments | Description |
|-----------|---------|-----------|-------------|
| `waf` | http, server, location | `on\|off` | Enable/disable WAF |
| `waf_mode` | http, server, location | `blacklist\|whitelist` | Operation mode |
| `waf_list` | http | `name path [tags]` | Define an IP list |
| `waf_enable_lists` | http, server, location | `name,...\|tag:name\|all` | Activate lists |
| `waf_disable_lists` | http, server, location | `name,...\|tag:name` | Deactivate lists |
| `waf_log_prefix` | http, server, location | `string` | Custom log prefix |

---

## IP List Format

Lists are plain text files with one entry per line:

```
# Comments start with #
# IPv4 addresses
192.168.1.100
10.0.0.50

# IPv4 CIDR ranges
192.168.0.0/24
10.0.0.0/8

# IPv6 addresses
2001:db8::1
::ffff:192.168.1.1

# IPv6 CIDR ranges
2001:db8::/32
```

---

## Installation

🚧 **Packages coming soon via openSUSE Build Service (OBS)**

Planned distribution support:

| Distribution | Versions |
|--------------|----------|
| Debian | 11, 12, 13 |
| Ubuntu | 22.04, 24.04, 25.04 |
| Fedora | 41, 42 |
| openSUSE | Tumbleweed, Leap 15.6, 16.0 |
| RHEL/Rocky/Alma | 8, 9 |

---

## Building from Source

Requirements:

- nginx source code (matching your nginx version)
- GCC and make
- PCRE and zlib development libraries

```bash
# Download nginx source
wget https://nginx.org/download/nginx-1.27.4.tar.gz
tar xzf nginx-1.27.4.tar.gz
cd nginx-1.27.4

# Configure with the module
./configure --add-dynamic-module=/path/to/nginx-waf/src

# Build the module
make modules

# Install (as root)
cp objs/ngx_http_waf_module.so /usr/lib64/nginx/modules/
```

---

## Works Well With

nginx-waf is designed to complement existing nginx modules:

| Module | Use Case |
|--------|----------|
| `ngx_http_realip_module` | Get real client IP behind proxies/CDN |
| `ngx_http_limit_req_module` | Rate limiting |
| `ngx_http_geo_module` | Geographic restrictions |
| `ngx_http_access_module` | Simple allow/deny rules |

Example with Real IP:

```nginx
http {
    # Trust Cloudflare IPs
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    real_ip_header CF-Connecting-IP;
    
    # WAF checks real client IP
    waf_list threats "/etc/nginx/waf/threats.txt";
    waf on;
    waf_mode blacklist;
    waf_enable_lists threats;
}
```

---

## Roadmap

### v0.2.1 - Core Module ✅ (Current)

- [x] Project setup and documentation
- [x] Basic module with `waf on|off`
- [x] Single IP list support
- [x] Multiple named lists with tags
- [x] Blacklist and whitelist modes
- [x] IPv4 and IPv6 with CIDR
- [x] `waf_enable_lists` and `waf_disable_lists` directives
- [x] Tag-based list selection (`tag:name`)
- [x] Context inheritance (http → server → location)
- [x] GitHub Actions CI/CD (x86_64 + ARM64)
- [ ] OBS packages (in progress)

### v1.0.0 - Stable Release (Target: Q2 2026)

- [ ] Community testing and feedback
- [ ] Performance benchmarks
- [ ] OBS packages for major distributions
- [ ] Security review

### v2.0.0 - Extensions (Future)

See **Planned Extensions** section below for details on future companion projects.

---

## Planned Extensions

These companion projects are planned for future development after nginx-waf v1.0 is stable. They will be separate repositories.

| Project | Language | Description |
|---------|----------|-------------|
| **nginx-waf-api** | Go | REST API daemon for dynamic IP list management without nginx reloads |
| **nginx-waf-ui** | Go | Web-based dashboard for managing lists, viewing stats, and configuration |
| **nginx-waf-feeds** | Go | Automatic threat feed updater (Cloudflare, Tor exits, Spamhaus, etc.) |
| **nginx-waf-lua** | Lua | OpenResty/Lua integration for scripted WAF logic and custom responses |

### Architecture Overview

```
                                ┌─────────────────┐
                                │  nginx-waf-ui   │
                                │  (Web Dashboard)│
                                └────────┬────────┘
                                         │
┌─────────────────┐            ┌─────────▼────────┐            ┌─────────────────┐
│ nginx-waf-feeds │───────────▶│  nginx-waf-api   │◀───────────│   CLI / Scripts │
│ (Feed Updater)  │            │   (REST API)     │            │                 │
└─────────────────┘            └─────────┬────────┘            └─────────────────┘
                                         │
                               ┌─────────▼────────┐
                               │   IP List Files  │
                               │ /etc/nginx/waf/  │
                               └─────────┬────────┘
                                         │
                               ┌─────────▼────────┐
                               │    nginx-waf     │◀──── nginx-waf-lua
                               │   (C Module)     │      (Lua bindings)
                               └──────────────────┘
```

### Status

| Project | Status |
|---------|--------|
| nginx-waf | 🟡 In Development |
| nginx-waf-api | 🔴 Planned |
| nginx-waf-ui | 🔴 Planned |
| nginx-waf-feeds | 🔴 Planned |
| nginx-waf-lua | 🔴 Planned |

> These projects will be started after nginx-waf v1.0 reaches stable release.

---

## Contributing

We welcome contributions! This is an experimental project and community input is valuable.

### How to Contribute

1. Check [Issues](https://github.com/RumenDamyanov/nginx-waf/issues) for `good first issue` labels
2. Read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
3. Open a discussion for ideas or questions
4. Submit focused, well-tested PRs

### What We Need

- Testing on different nginx versions and distributions
- Documentation improvements
- Example configurations
- Code review and security feedback

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Related Projects

- [nginx-torblocker](https://github.com/RumenDamyanov/nginx-torblocker) - Block Tor exit nodes (simpler, single-purpose)
- [nginx-cf-realip](https://github.com/RumenDamyanov/nginx-cf-realip) - Cloudflare real IP handling

---

## Support the Project

If you find this project interesting:

- ⭐ Star the repository
- 💖 [GitHub Sponsors](https://github.com/sponsors/RumenDamyanov)
- ☕ [Ko-fi](https://ko-fi.com/rumenx)
- ☕ [Buy Me a Coffee](https://buymeacoffee.com/rumenx)

See [FUNDING.md](FUNDING.md) for more options.

---

## License

[BSD 3-Clause License](LICENSE.md)

---

## Security

Found a security issue? Please see our [Security Policy](SECURITY.md) for responsible disclosure.

---

<p align="center">
  <strong>⚠️ Experimental - Use at Your Own Risk</strong><br>
  <em>Contributions and ideas welcome!</em>
</p>
