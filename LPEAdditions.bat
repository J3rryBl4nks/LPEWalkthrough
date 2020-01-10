@echo #This script will clean up all your old logs that are text files, and is running as system in a scheduled task every minute.> C:\Temp\Cleanup.ps1
@echo Remove-Item C:\Temp\*.txt>> C:\Temp\Cleanup.ps1

schtasks /CREATE /SC Minute /TN Cleanup /TR "powershell.exe -exec bypass -nop C:\Temp\Cleanup.ps1" /RU SYSTEM