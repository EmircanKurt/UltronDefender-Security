; Inno Setup Script for Ultron Defender Total Security
#define MyAppName "Ultron Defender Total Security"
#define MyAppVersion "3.2.1"
#define MyAppPublisher "EmircanKurt"
#define MyAppURL "https://github.com/EmircanKurt/UltronDefender-Security"
#ifndef AppPublishDir
  #define AppPublishDir SourcePath + "artifacts\release-3.2.1\payload"
#endif
#ifndef SetupOutputDir
  #define SetupOutputDir SourcePath + "artifacts\release-3.2.1"
#endif
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
OutputDir={#SetupOutputDir}
OutputBaseFilename=UltronDefenderSetup
SetupIconFile=ultron_shield.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/normal
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0.17763
AppMutex=UltronDefender_SingleInstance_Mutex,Global\UltronDefender_SingleInstance_Mutex
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[CustomMessages]
english.AutoStartDesc=Start Ultron Defender automatically in background when Windows starts
english.AutoStartGroup=Startup Settings:
english.InstallServiceDesc=Install AegisPC Background Protection Service (recommended for real-time monitoring)
english.InstallServiceGroup=Service Settings:
english.AlreadyInstalledTitle=Ultron Defender Total Security is Already Installed
english.AlreadyInstalledMsg=Ultron Defender Total Security is already installed on your computer.%n%nInstalled Version: %1%nInstall Path: %2%n%nDo you want to reinstall or upgrade to version %3?
turkish.AutoStartDesc=Windows başladığında otomatik olarak arka planda çalıştır
turkish.AutoStartGroup=Başlangıç Ayarları:
turkish.InstallServiceDesc=AegisPC Arka Plan Koruma Servisini Kur (gerçek zamanlı koruma için önerilir)
turkish.InstallServiceGroup=Servis Ayarları:
turkish.AlreadyInstalledTitle=Ultron Defender Total Security Zaten Kurulu
turkish.AlreadyInstalledMsg=Ultron Defender Total Security bilgisayarınızda zaten kurulu durumda.%n%nKurulu Sürüm: %1%nKurulum Konumu: %2%n%nYeniden kurmak veya sürüm %3'e güncellemek istiyor musunuz?

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:AutoStartDesc}"; GroupDescription: "{cm:AutoStartGroup}"
Name: "installservice"; Description: "{cm:InstallServiceDesc}"; GroupDescription: "{cm:InstallServiceGroup}"

[Files]
Source: "{#AppPublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\ultron_shield.ico"
Name: "{group}\Ultron Defender Kaldır (Uninstall)"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\ultron_shield.ico"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "UltronDefender"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart
Root: HKLM; Subkey: "Software\Classes\*\shell\UltronDefenderScan"; ValueType: string; ValueName: ""; ValueData: "🛡️ Ultron Defender ile Tara"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\UltronDefenderScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\UltronDefenderScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" /scan ""%1"""; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\UltronDefenderScan"; ValueType: string; ValueName: ""; ValueData: "🛡️ Ultron Defender ile Tara"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\UltronDefenderScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\UltronDefenderScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" /scan ""%1"""; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\UltronDefenderScan"; ValueType: string; ValueName: ""; ValueData: "🛡️ Ultron Defender ile Tara"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\UltronDefenderScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\UltronDefenderScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" /scan ""%V"""; Flags: uninsdeletekey

[Run]
Filename: "{sys}\sc.exe"; Parameters: "create ""AegisPC Protection Service"" binPath= ""\""{app}\Service\AegisPC.Service.exe\"""" start= auto displayname= ""AegisPC Protection Service"""; Flags: runhidden; StatusMsg: "Ultron Defender Koruma Servisi kuruluyor..."; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "failure ""AegisPC Protection Service"" reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "start ""AegisPC Protection Service"""; Flags: runhidden; StatusMsg: "Ultron Defender Koruma Servisi başlatılıyor..."; Tasks: installservice
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
function InitializeUninstall(): Boolean;
var
  ErrorCode: Integer;
  ImagePath: String;
  ExpectedPath: String;
begin
  Result := True;
  ExpectedPath := ExpandConstant('{app}\Service\AegisPC.Service.exe');
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Services\AegisPC Protection Service', 'ImagePath', ImagePath) then
    if (CompareText(Trim(ImagePath), ExpectedPath) = 0) or
       (CompareText(Trim(ImagePath), '"' + ExpectedPath + '"') = 0) then
    begin
      Exec(ExpandConstant('{sys}\sc.exe'), 'stop "AegisPC Protection Service"', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
      Exec(ExpandConstant('{sys}\sc.exe'), 'delete "AegisPC Protection Service"', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
    end;
  { Inno removes only recorded installed files. Unknown user data and quarantine are preserved. }
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
