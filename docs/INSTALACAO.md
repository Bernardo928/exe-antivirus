# Instalação e desinstalação

## Windows

`ExeAntivirus-<versão>-windows-x64-instalador.exe` (artefato do CI). Pede permissão de administrador e:

- instala em `C:\Program Files\EXE Antivirus` (só administradores alteram os arquivos — base da autoproteção);
- cria atalho no menu Iniciar (e na área de trabalho, opcional);
- opção "Proteger o computador desde a inicialização": tarefa agendada **EXE Antivirus** no logon com o nível
  mais alto de privilégio disponível (firewall, DNS e proteção ao ligar funcionam sem pedir UAC a cada boot);
- opção "Analisar scripts do PowerShell por dentro": liga o registro de blocos de script do Windows
  (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`).

Instalação silenciosa: `instalador.exe /VERYSILENT /TASKS="autostart,pslog"`.

### Desinstalar

Configurações do Windows → Aplicativos → EXE Antivirus → Desinstalar (ou `unins000.exe /VERYSILENT`).
O desinstalador fecha o antivírus e **desfaz tudo o que ele mudou**: tarefa agendada, DNS (volta ao original),
sites bloqueados no arquivo `hosts`, regras de firewall criadas por ele e o registro do PowerShell (se foi o
instalador que ligou). Testado no CI a cada envio. A pasta de dados (`%LOCALAPPDATA%\ExeAntivirus`: quarentena,
histórico, incidentes) é mantida para o usuário decidir.

## Linux

`ExeAntivirus-<versão>-linux-x64.AppImage`: `chmod +x` e abrir. No primeiro uso ele se adiciona ao menu de
aplicativos e à inicialização automática da sessão.

Recursos que precisam de root (firewall, DNS do sistema, arquivo hosts): execute com `sudo`, ou instale o
serviço de boot que reaplica os bloqueios do firewall antes do login:

```bash
sudo ./ExeAntivirus-*.AppImage --install-system --autostart --boot-service
```

Bloquear a internet de um programa específico exige o OpenSnitch (`sudo apt install opensnitch`).

### Desinstalar

```bash
./ExeAntivirus-*.AppImage --uninstall-system        # como usuário
sudo ./ExeAntivirus-*.AppImage --uninstall-system   # também remove o serviço de boot e as regras de firewall
```

Depois, apague o arquivo `.AppImage`. Os dados ficam em `~/.local/share/exe-antivirus`.

## Verificar a instalação

```bash
ExeAntivirus --selftest     # motor, quarentena, Sala de Análise, autoexclusão
ExeAntivirus --selfcheck    # integridade dos arquivos do programa, regras, configurações, histórico, quarentena
```
