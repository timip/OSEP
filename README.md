# PEN-300 / OSEP

Public resources for PEN-300 Training. 

## Operating System and Programming Theory

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

## Introduction to Antivirus Evasion

## Advanced Antivirus Evasion

## Application Whitelisting

## Bypassing Network Filters

## Linux Post-Exploitation

## Kiosk Breakouts

## Windows Credentials

## Windows Lateral Movement

## Linux Lateral Movement

## Microsoft SQL Attacks

## Active Directory Exploitation

## Combining the Pieces

## Trying Harder: The Labs
