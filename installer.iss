; Experimental per-user preview. No service, driver, firewall or automatic startup changes.
#define MyAppName "Ultron Defender Preview"
#ifndef MyAppVersion
  #define MyAppVersion "3.2.2-preview.20261009"
#endif
#define MyAppPublisher "EmircanKurt"
#define MyAppURL "https://github.com/EmircanKurt/UltronDefender-Security"
#ifndef AppPublishDir
  #define AppPublishDir SourcePath + "artifacts\preview-3.2.2\payload"
#endif
#ifndef SetupOutputDir
  #define SetupOutputDir SourcePath + "artifacts\preview-3.2.2"
#endif
#define MyAppExeName "UltronDefender.exe"

[Setup]
; Separate identity/path keeps the previous installation recoverable.
AppId={{B0894480-4DA1-4ED8-B808-FD9347C9D7CB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputDir={#SetupOutputDir}
OutputBaseFilename=UltronDefenderSetup-3.2.2-preview.20261009
SetupIconFile=ultron_shield.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/normal
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0.17763
AppMutex=UltronDefender_SingleInstance_Mutex,Global\UltronDefender_SingleInstance_Mutex
CloseApplications=no
RestartApplications=no
UsePreviousAppDir=no
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#AppPublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\ultron_shield.ico"
Name: "{group}\Uninstall Preview"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\ultron_shield.ico"; Tasks: desktopicon

; No [Run], SCM, autostart or shell-registration steps.
; Installed payload removal leaves unknown user/vault data untouched.
