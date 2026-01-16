# IP List Format

nginx-waf uses plain text files for IP lists, one entry per line.

## Supported Formats

| Format | Example | Description |
|--------|---------|-------------|
| IPv4 address | `192.168.1.100` | Single IPv4 address |
| IPv4 CIDR | `192.168.0.0/24` | IPv4 network range |
| IPv6 address | `2001:db8::1` | Single IPv6 address |
| IPv6 CIDR | `2001:db8::/32` | IPv6 network range |

## Syntax Rules

- One IP or CIDR per line
- Lines starting with `#` are comments
- Empty lines are ignored
- Leading/trailing whitespace is trimmed
- Invalid entries are logged and skipped

## Example File

```
# My blacklist
# Last updated: 2025-01-16

# Known bad actors
192.0.2.1
192.0.2.100

# Entire network to block
198.51.100.0/24

# IPv6 entries
2001:db8::dead:beef
2001:db8:bad::/48
```

## Best Practices

1. **Use comments** to document why IPs are listed
2. **Group related IPs** with headers
3. **Use CIDR** for ranges instead of listing individual IPs
4. **Keep files manageable** (nginx-waf limits to 10MB per file)
5. **Review regularly** to remove stale entries

## Test IP Ranges

These ranges are reserved for documentation and testing:

- IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- IPv6: `2001:db8::/32`

Use these for testing without affecting real traffic.
