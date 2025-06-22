# subsagg

**subsagg** is a small and fast Go tool for subdomain enumeration aggregation. It runs multiple popular subdomain tools in parallel, merges their results, and outputs unique subdomains.

## Features

- Runs many tools (subfinder, amass, assetfinder, and more)
- Easy YAML configuration: add or remove tools as you wish
- Customizable wordlist and resolvers
- Skips tools that are not installed
- Simple CLI, no dependencies except Go and your subdomain tools

## Installation

Requires Go 1.20+.

```bash
go install github.com/xqu3ry/subsagg@latest
```

Make sure `$HOME/go/bin` is in your `$PATH`.

## Usage

```bash
subagg run example.com
```

Results are saved to `subdomains_example.com.txt`.

Show config:

```bash
subagg config show
```

Add a tool:

```bash
subagg config add-tool mytool "mytool,-d,{domain}"
```

## Configuration

The first run creates `subsagg.yaml` if it does not exist.  
Edit it to add or remove tools, change wordlist, or resolvers.

Example:

```yaml
tools:
  - name: subfinder
    cmd: ["subfinder", "-d", "{domain}", "-silent"]
  - name: amass
    cmd: ["amass", "enum", "-passive", "-d", "{domain}"]
wordlist: "/usr/share/wordlists/subdomains-top1million-5000.txt"
resolvers: "/etc/resolv.conf"
```
