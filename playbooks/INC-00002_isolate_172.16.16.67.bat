@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.16.67" dir=in action=block remoteip=172.16.16.67
netsh advfirewall firewall add rule name="Block_172.16.16.67_out" dir=out action=block remoteip=172.16.16.67
echo Isolated 172.16.16.67
