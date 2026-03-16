@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.7.220" dir=in action=block remoteip=172.16.7.220
netsh advfirewall firewall add rule name="Block_172.16.7.220_out" dir=out action=block remoteip=172.16.7.220
echo Isolated 172.16.7.220
