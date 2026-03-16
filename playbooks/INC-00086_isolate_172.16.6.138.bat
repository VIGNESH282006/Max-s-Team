@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.6.138" dir=in action=block remoteip=172.16.6.138
netsh advfirewall firewall add rule name="Block_172.16.6.138_out" dir=out action=block remoteip=172.16.6.138
echo Isolated 172.16.6.138
