@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_192.168.251.22" dir=in action=block remoteip=192.168.251.22
netsh advfirewall firewall add rule name="Block_192.168.251.22_out" dir=out action=block remoteip=192.168.251.22
echo Isolated 192.168.251.22
