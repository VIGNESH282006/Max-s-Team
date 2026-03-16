@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_192.168.147.220" dir=in action=block remoteip=192.168.147.220
netsh advfirewall firewall add rule name="Block_192.168.147.220_out" dir=out action=block remoteip=192.168.147.220
echo Isolated 192.168.147.220
