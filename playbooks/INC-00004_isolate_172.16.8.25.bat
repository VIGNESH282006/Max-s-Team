@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.8.25" dir=in action=block remoteip=172.16.8.25
netsh advfirewall firewall add rule name="Block_172.16.8.25_out" dir=out action=block remoteip=172.16.8.25
echo Isolated 172.16.8.25
