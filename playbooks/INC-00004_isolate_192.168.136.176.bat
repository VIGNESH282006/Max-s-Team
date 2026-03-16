@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_192.168.136.176" dir=in action=block remoteip=192.168.136.176
netsh advfirewall firewall add rule name="Block_192.168.136.176_out" dir=out action=block remoteip=192.168.136.176
echo Isolated 192.168.136.176
