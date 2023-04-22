# FuckTCP

spoof your tcp.
## Usage:
```
iptables -A OUTPUT -p tcp --tcp-flags RST RST -d <TARGET> -j DROP
python fucktcp.py <interface> <target> <spoof> <targetport> <spoofport>
```
