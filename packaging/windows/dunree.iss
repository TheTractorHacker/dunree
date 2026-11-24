; Inno Setup 6 script for the Dunree Windows installer.
;
; Build on Windows (Inno Setup 6.3 or newer), one installer per CPU architecture:
;
;   iscc /DAppVersion=1.0.0-beta.1 /DArch=amd64 /DSourceExe=..\..\dist\dunree_windows_amd64.exe ^
;        /DOutputDir=..\..\dist packaging\windows\dunree.iss
;   iscc /DAppVersion=1.0.0-beta.1 /DArch=arm64 /DSourceExe=..\..\dist\dunree_windows_arm64.exe ^
;        /DOutputDir=..\..\dist packaging\windows\dunree.iss
;
; Result: dunree_<version>_windows_<arch>_setup.exe
;
; The installer copies dunree.exe to {autopf}\Dunree, registers the Windows service with
; "dunree.exe service install" (data folder %ProgramData%\Dunree) and starts it. Uninstall
; removes the service and the program; the data folder is kept.
;
; Code signing is not configured and no key or certificate belongs in this repository. To
; sign, define a sign tool in the Inno Setup IDE or pass /Ssigntool=... to iscc and add
; "SignTool=signtool" and "SignedUninstaller=yes" to [Setup].

#ifndef AppVersion
  #error Pass /DAppVersion=x.y.z
#endif
#ifndef Arch
  #define Arch "amd64"
#endif
#ifndef SourceExe
  #define SourceExe "..\..\dist\dunree_windows_" + Arch + ".exe"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif
#define RepoRoot "..\.."

[Setup]
; Do not change AppId: it is how an upgrade finds the installed version.
AppId={{B90F869B-9837-421A-A8F9-0A6021BC18A5}
AppName=Dunree
AppVersion={#AppVersion}
AppVerName=Dunree {#AppVersion}
AppPublisher=Foley IT
AppComments=Reverse proxy and web gateway. Based on Zoraxy v3.3.6 by tobychui and imuslab (AGPL-3.0).
DefaultDirName={autopf}\Dunree
DisableProgramGroupPage=yes
DisableDirPage=auto
LicenseFile={#RepoRoot}\LICENSE
InfoBeforeFile={#RepoRoot}\NOTICE
OutputDir={#OutputDir}
OutputBaseFilename=dunree_{#AppVersion}_windows_{#Arch}_setup
SetupIconFile={#RepoRoot}\brand\favicon.ico
UninstallDisplayIcon={app}\dunree.exe
UninstallDisplayName=Dunree
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
MinVersion=10.0
CloseApplications=no
#if Arch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "service"; Description: "Install Dunree as a Windows service and start it"
Name: "firewall"; Description: "Allow inbound TCP 80 and 443 and UDP 443 in Windows Firewall"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "dunree.exe"; Flags: ignoreversion
Source: "{#RepoRoot}\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "{#RepoRoot}\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion
Source: "{#RepoRoot}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-windows.txt"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; "service install" fails harmlessly when the service is already registered (upgrade): its flags and data folder stay.
Filename: "{app}\dunree.exe"; Parameters: "service install"; Flags: runhidden; Tasks: service; StatusMsg: "Registering the Dunree service..."
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Dunree HTTP (TCP 80)"" dir=in action=allow protocol=TCP localport=80 program=""{app}\dunree.exe"""; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Dunree HTTPS (TCP 443)"" dir=in action=allow protocol=TCP localport=443 program=""{app}\dunree.exe"""; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Dunree HTTP/3 (UDP 443)"" dir=in action=allow protocol=UDP localport=443 program=""{app}\dunree.exe"""; Flags: runhidden; Tasks: firewall
Filename: "{app}\dunree.exe"; Parameters: "service start"; Flags: runhidden; Tasks: service; StatusMsg: "Starting the Dunree service..."

[UninstallRun]
Filename: "{app}\dunree.exe"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "DunreeService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Dunree HTTP (TCP 80)"""; Flags: runhidden; RunOnceId: "DunreeFw80"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Dunree HTTPS (TCP 443)"""; Flags: runhidden; RunOnceId: "DunreeFw443"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Dunree HTTP/3 (UDP 443)"""; Flags: runhidden; RunOnceId: "DunreeFwQuic"

[Code]
// Upgrade: stop the running service before the program file is replaced. The [Run] section starts it again.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if FileExists(ExpandConstant('{app}\dunree.exe')) then
    Exec(ExpandConstant('{app}\dunree.exe'), 'service stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
