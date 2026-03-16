@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.22.77" dir=in action=block remoteip=172.16.22.77
netsh advfirewall firewall add rule name="Block_172.16.22.77_out" dir=out action=block remoteip=172.16.22.77
echo Isolated 172.16.22.77
