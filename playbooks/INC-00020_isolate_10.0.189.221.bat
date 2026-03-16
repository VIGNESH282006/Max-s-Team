@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_10.0.189.221" dir=in action=block remoteip=10.0.189.221
netsh advfirewall firewall add rule name="Block_10.0.189.221_out" dir=out action=block remoteip=10.0.189.221
echo Isolated 10.0.189.221
