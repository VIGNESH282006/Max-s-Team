@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_10.0.41.223" dir=in action=block remoteip=10.0.41.223
netsh advfirewall firewall add rule name="Block_10.0.41.223_out" dir=out action=block remoteip=10.0.41.223
echo Isolated 10.0.41.223
