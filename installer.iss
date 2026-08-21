; Inno Setup Script for Ultron Defender Total Security
#define MyAppName "Ultron Defender Total Security"
#define MyAppVersion "3.2.0"
#define MyAppPublisher "Ultron Security Technologies"
#define MyAppURL "https://github.com/UltronDefender"
#define MyAppExeName "UltronDefender.exe"
#define MyUninstallerExeName "Uninstall.exe"

[Setup]
AppId={{E58E9715-7DA2-4C77-8E28-662B75003E92}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputDir=c:\Users\PC\Documents\gemini virüs program
OutputBaseFilename=UltronDefender_Setup_v3.2
SetupIconFile=c:\Users\PC\Documents\gemini virüs program\ultron_shield.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
AppMutex=UltronDefender_SingleInstance_Mutex,Global\UltronDefender_SingleInstance_Mutex
CloseApplications=yes
RestartApplications=yes
UsePreviousAppDir=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[CustomMessages]
english.AutoStartDesc=Start Ultron Defender automatically in background when Windows starts
english.AutoStartGroup=Startup Settings:
english.AlreadyInstalledTitle=Ultron Defender Total Security is Already Installed
english.AlreadyInstalledMsg=Ultron Defender Total Security is already installed on your computer.%n%nInstalled Version: %1%nInstall Path: %2%n%nDo you want to reinstall or upgrade to version %3?
turkish.AutoStartDesc=Windows başladığında otomatik olarak arka planda çalıştır
turkish.AutoStartGroup=Başlangıç Ayarları:
turkish.AlreadyInstalledTitle=Ultron Defender Total Security Zaten Kurulu
turkish.AlreadyInstalledMsg=Ultron Defender Total Security bilgisayarınızda zaten kurulu durumda.%n%nKurulu Sürüm: %1%nKurulum Konumu: %2%n%nYeniden kurmak veya sürüm %3'e güncellemek istiyor musunuz?

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:AutoStartDesc}"; GroupDescription: "{cm:AutoStartGroup}"

[Files]
Source: "c:\Users\PC\Documents\gemini virüs program\AegisPC_App\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Ultron Defender Kaldır (Uninstall)"; Filename: "{app}\{#MyUninstallerExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "UltronDefender"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart
Root: HKCU; Subkey: "Software\Classes\*\shell\UltronDefenderScan"; ValueType: string; ValueName: ""; ValueData: "🛡️ Ultron Defender ile Tara"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\UltronDefenderScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\UltronDefenderScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" /scan ""%1"""; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\UltronDefenderScan"; ValueType: string; ValueName: ""; ValueData: "🛡️ Ultron Defender ile Tara"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\UltronDefenderScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\UltronDefenderScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" /scan ""%1"""; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\UltronDefenderScan"; ValueType: string; ValueName: ""; ValueData: "🛡️ Ultron Defender ile Tara"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\UltronDefenderScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\UltronDefenderScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" /scan ""%V"""; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeUninstall(): Boolean;
var
  ErrorCode: Integer;
begin
  Result := True;
  Exec('taskkill.exe', '/f /im UltronDefender.exe', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
  Exec('taskkill.exe', '/f /im "Ultron Defender Total Security.exe"', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
  Exec('taskkill.exe', '/f /im "Ultron Defender Security.exe"', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
  Exec('taskkill.exe', '/f /im AegisPC.exe', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
end;

function InitializeSetup(): Boolean;
var
  InstalledVer: String;
  InstallPath: String;
  KeyName: String;
begin
  Result := True;
  KeyName := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1';
  
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, KeyName, 'DisplayVersion', InstalledVer) or
     RegQueryStringValue(HKEY_CURRENT_USER, KeyName, 'DisplayVersion', InstalledVer) then
  begin
    if not RegQueryStringValue(HKEY_LOCAL_MACHINE, KeyName, 'InstallLocation', InstallPath) then
    begin
      RegQueryStringValue(HKEY_CURRENT_USER, KeyName, 'InstallLocation', InstallPath);
    end;
    
    if InstallPath = '' then
    begin
      InstallPath := ExpandConstant('{autopf}\{#MyAppName}');
    end;
    
    if MsgBox(FmtMessage(CustomMessage('AlreadyInstalledMsg'), [InstalledVer, InstallPath, '{#MyAppVersion}']), 
              mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
      Exit;
    end;
  end;
end;
