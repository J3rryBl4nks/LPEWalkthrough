### Windows Privesc Methodology ####

Gathering information is important, once you get a shell on a Windows machine, you want to find out the patch level of the machine and look for custom software.

My methodology is as follows:

1. Attempt to run automated privesc check scripts and executables:
  a. Start with PowerUp/SharpUp
  b. Move to Seatbelt/winPEAS
2. If there is AV that is blocking my attempts, switch to manual enumeration.
  a. Manual OS enumeration steps: 
    http://www.fuzzysecurity.com/tutorials/16.html
    https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
3. Attempt to use AV evasion frameworks for my shell.
  a. There are a lot of AV evasion frameworks, and a lot of it comes down to knowing the AV you are facing.
    1. If it's defender, can you install another AV over the top?
    2. If it's signature based, can you recompile and modify the payload so that the sig based AV won't catch it?

Look for custom software running on the system. Custom software is usually the easiest way to elevate your privileges in real world scenarios. Most custom software doesn't account for Privilege Escalation as a part of their threat model.

Any non-standard Windows Services would be the first target.

1. Look at the service binary permissions.
2. Look at the service config permissions.
3. Can you install the service in a test VM on your side? Is it free software?
4. Can you reverse engineer the software?
  1. Is the service loading any .dll files from insecure directories. (Procmon.exe)
  2. Is the service loading any .exe files from insecure directories. (Procmon.exe)
5. Is the service vulnerable to a buffer overflow?
6. Is the service getting patch information from a location you can control?

Once you have audited the permissions of the custom windows services, look at custom software that might require admin privileges to run.
1. Can you replace portions of that software that requires admin privileges?
2. Can you inject your exe/dll into the execution path of this software?

If we can't find any software that is custom installed that seems vulnerable, can we pivot to another machine?
1. Stored credentials?
2. API keys.

If I can't pivot, is it worth trying to blow my opsec to get the user to give me admin?
1. There are a lot of tools for popping something into the face of the user to try to get admin.
