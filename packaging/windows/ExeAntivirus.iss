; Instalador do EXE Antivirus para Windows (Inno Setup 6)
; Compilar:  python tools/build.py --installer      (ou: iscc /DAppVersion=1.1.0 ExeAntivirus.iss)

#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif
#define AppName "EXE Antivirus"
#define AppExe "ExeAntivirus.exe"

[Setup]
AppId={{6F2C9A41-3B7E-4D21-9E58-EA1C0B7D5F30}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=EXE Antivirus
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Instalador do {#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=ExeAntivirus-{#AppVersion}-windows-x64-instalador
SetupIconFile=..\..\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
CloseApplications=force
RestartApplications=no
MinVersion=10.0

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "autostart"; Description: "Proteger o computador desde a inicialização (recomendado)"; GroupDescription: "Proteção:"
Name: "pslog"; Description: "Analisar scripts do PowerShell por dentro (liga o registro de scripts do Windows)"; GroupDescription: "Proteção:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\..\dist\ExeAntivirus\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "--install-system --autostart"; Flags: runhidden waituntilterminated; Tasks: autostart and not pslog; StatusMsg: "Configurando a proteção desde a inicialização..."
Filename: "{app}\{#AppExe}"; Parameters: "--install-system --autostart --pslog"; Flags: runhidden waituntilterminated; Tasks: autostart and pslog; StatusMsg: "Configurando a proteção desde a inicialização..."
Filename: "{app}\{#AppExe}"; Parameters: "--install-system --pslog"; Flags: runhidden waituntilterminated; Tasks: pslog and not autostart; StatusMsg: "Ligando a análise de scripts..."
Filename: "{app}\{#AppExe}"; Description: "Abrir o {#AppName} agora"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; fecha o antivírus aberto e desfaz tudo o que ele mudou no sistema (tarefa, DNS, hosts, firewall)
Filename: "{app}\{#AppExe}"; Parameters: "--uninstall-system"; Flags: runhidden waituntilterminated; RunOnceId: "DesfazerSistema"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
