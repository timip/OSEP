# PEN-300 / OSEP

Public resources for PEN-300 Training. 

## 1. Evasion Techniques and Breaching Defenses: General Course Information

## 2. Operating System and Programming Theory

## 3. Client Side Code Execution With Office
- 3.1.3.1: JavaScript
  - https://developer.mozilla.org/en-US/docs/Web/API/Navigator/msSaveBlob
  - https://docs.microsoft.com/en-us/previous-versions/hh772331(v=vs.85)
- 3.2.2.1: MyMarco
  - http://libertyboy.free.fr/computing/reference/envariables/
  - https://www.youtube.com/watch?v=fG5PsO0L8bI
- 3.2.3.1: MyMarco and PowerShell
  - https://www.abatchy.com/2017/03/powershell-download-file-one-liners
- 3.4.3.1: Calling Win32 APIs from VBA
  - https://sites.google.com/site/jrlhost/links/excelcdll
  - MessageBoxA
    - https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
    - https://stackov=erflow.com/questions/60753153/custom-message-box-code-fails-without-out-warning-in-latest-version-of-excel-on
    - https://www.cadsharp.com/docs/Win32API_PtrSafe.txt
  - FindWindowA
    - https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa
    - http://users.skynet.be/am044448/Programmeren/VBA/vba_class_names.htm
- 3.5.1.1: Calling Win32 APIs from PowerShell
  - http://pinvoke.net/default.aspx/advapi32/GetUserName.html
- 3.5.2.1: Porting Shellcode Runner to PowerShell
  - http://pinvoke.net/default.aspx/kernel32/WaitForSingleObject.html
- 3.6.2.1: Leveraging UnsafeNativeMethods
  - https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
  - https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
- 3.6.3.1: DelegateType Reflection
  - https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec

## 4. Client Side Code Execution With Windows Script Host
- 4.1.1.1: Creating a Basic Dropper in Jscript
  - https://stackoverflow.com/questions/1050293/vbscript-using-wscript-shell-to-execute-a-command-line-program-that-accesses-ac
- 4.1.2.1: Jscript Meterpreter Dropper
  - https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms760236%28v%3dvs.85%29 (It is ServerXMLHTTP. Not XMLHTTP)
  - https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/x05fawxd(v=vs.84)
- 4.2.2.1: DotNetToJscript
  - https://stackoverflow.com/questions/181719/how-do-i-start-a-process-from-c

## 5. Process Injection and Migration
- 5.1.2.1: Process Injection in C# (VirtualAlloc and WriteProcessMemory Injection)
  - http://pinvoke.net/default.aspx/kernel32/OpenProcess.html
  - http://pinvoke.net/default.aspx/kernel32/VirtualAllocEx.html
  - http://pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
  - http://pinvoke.net/default.aspx/kernel32/CreateRemoteThread.html
  - https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.getprocessesbyname?view=netframework-4.8
  - https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.id?view=net-5.0
  - https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1
- 5.1.2.2: Extra Mile (NTMap Injection)
  - https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection
  - http://joyasystems.com/list-of-ntstatus-codes
  - NtCreationSection
    - http://pinvoke.net/default.aspx/ntdll/NtCreateSection.html
    - https://stackoverflow.com/questions/683491/how-to-declarate-large-integer-in-c-sharp
  - NtMapViewOfSection
    - http://pinvoke.net/default.aspx/ntdll/NtMapViewOfSection.html
    - http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
    - https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
  - NtUnmapViewOfSection
    - http://pinvoke.net/default.aspx/ntdll/NtUnmapViewOfSection.html
  - NtClose
    - http://pinvoke.net/default.aspx/ntdll/NtClose.html 

## 6. Introduction to Antivirus Evasion
- 6.6.2.1: Non-emulated APIs
  - https://docs.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc
  - http://pinvoke.net/default.aspx/kernel32/FlsAlloc.html
  - https://social.msdn.microsoft.com/Forums/en-US/c85f867b-66f8-45bd-a105-a984d80bd720/flsoutofindexes?forum=winappswithnativecode
- 6.7.2.1: Stomping On Microsoft Word
  - https://github.com/outflanknl/EvilClippy
- 6.8.3.1: Obfuscating VBA
  - https://download.serviio.org/releases/serviio-1.8-win-setup.exe
  - https://www.exploit-db.com/exploits/41959
  - https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
  - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/1809%20Redstone%205%20(October%20Update)/_PEB32

## 7. Advanced Antivirus Evasion

- 7.4.2.1: Patching the internals
  - https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:O97M/OfficeWmiRunPowershell.B&ThreatID=2147772508
  - https://www.redteam.cafe/red-team/powershell/powershell-custom-runspace
  - https://isc.sans.edu/forums/diary/Powershell+Dropping+a+REvil+Ransomware/27012/
- 7.4.2.2: Extra Mile
  - https://rastamouse.me/blog/asb-bypass-pt3/

## 8. Application Whitelisting

- 8.2.2.2: Extra Mile
  - https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/
- 8.4.5.2: Extra Mile
  - https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild?view=vs-2019
  - https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks?view=vs-2019
  - https://docs.microsoft.com/en-us/visualstudio/msbuild/walkthrough-creating-an-inline-task?view=vs-2019
  - https://www.ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c
- 8.5.2.2: Extra Mile
  - https://github.com/cobbr/Covenant/wiki/Installation-And-Startup
  - https://dotnet.microsoft.com/download/dotnet/3.1
  - https://github.com/cobbr/Covenant/wiki

## 9. Bypassing Network Filters

- 9.3.1.1: Case Study: Bypassing Norton HIPS with Custom Certificates
  - https://www.hackingarticles.in/bypass-detection-for-meterpreter-shell-impersonate_ssl/
  - https://www.reddit.com/r/netsecstudents/comments/9xpfhy/problem_with_metasploit_using_an_ssl_certificate/
- 9.6.1.2: Extra Mile
  - https://censys.io/certificates?q=parsed.names:%20azureedge.net
- 9.6.2.2: Extra Mile
  - https://github.com/BC-SECURITY/Empire/issues/230

## 10. Linux Post-Exploitation

- 10.1.2.1: VIM Config Simple Keylogger
  - https://askubuntu.com/questions/284957/vi-getting-multiple-sorry-the-command-is-not-available-in-this-version-af
- 10.3.2.2: Extra Mile
  - https://stackoverflow.com/questions/20381812/mprotect-always-returns-invalid-arguments

## 11. Kiosk Breakouts
- 11.2.4.2: Extra Mile
  - https://developer.mozilla.org/en-US/docs/Web/API/Window/dump
  - https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.dom.window.dump.file

## 12. Windows Credentials
- 12.4.1.1: Memory Dump
  - https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf

## 13. Windows Lateral Movement
- 13.1.4.1: RDP as a Console
  - https://github.com/0xthirteen/SharpRDP
- 13.1.5.1: Stealing Clear Text Credentials from RDP
  - https://github.com/0x09AL/RdpThief
- 13.2.2.1: Implementing Fileless Lateral Movement in C#
  - https://github.com/Mr-Un1k0d3r/SCShell

## 14. Linux Lateral Movement
- 14.3: Kerberos on Linux
  - https://www.vgemba.net/microsoft/Kerberos-Linux-Windows-AD/
- 14.3.4.2: Extra Mile
  - https://github.com/GhostPack/Rubeus#dump
  - https://github.com/eloypgz/ticket_converter
  - https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
  - https://www.tarlogic.com/blog/how-to-attack-kerberos/

## 15. Microsoft SQL Attacks
- 15.2.1.1: Privilege Escalation using SQL Impersonation
  - https://www.microfocus.com/documentation/enterprise-developer/ed231/ETS/GUID-AF131F1C-54B8-4D25-8088-22A59C1AEA9F.html
- 15.3.1.1: Linked Server
  - https://documentation.nodinite.com/Documentation/InstallAndUpdate?doc=/Troubleshooting/About%20Linked%20Server%20RPC%20and%20RPC%20Out%20option
- 15.3.1.2: Extra Mile
  - https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/
- 15.3.2.2: Extra Mile
  - https://github.com/NetSPI/PowerUpSQL/wiki/Setting-Up-PowerUpSQL
  - https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

## 16. Active Directory Exploitation
- 16.2.1.1: Keroberos Unconstrained Delegation
  - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- 16.2.2.1: I Am a Domain Controller
  - https://github.com/leechristensen/SpoolSample
  - https://www.c-sharpcorner.com/article/how-to-fix-ps1-can-not-be-loaded-because-running-scripts-is-disabled-on-this-sys/
- 16.2.3.1: Constrained Delegation
  - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/configure-kerberos-constrained-delegation
- 16.2.4.1: Resource-Based Constrained Delegation
  - https://github.com/Kevin-Robertson/Powermad

## 17. Combining the Pieces

## 18. Trying Harder: The Labs
