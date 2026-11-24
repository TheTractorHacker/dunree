Dunree for Windows
==================

Dunree is a reverse proxy and web gateway, published by Foley IT under AGPL-3.0.
It is based on Zoraxy v3.3.6 by tobychui and imuslab (see NOTICE.txt) and is an
independent project that is not endorsed by them.

Contents of this folder

  dunree.exe               the program (one file, no runtime needed)
  install.ps1              installs the program and the Windows service
  uninstall.ps1            removes them (keeps your data)
  LICENSE.txt              GNU Affero General Public License, version 3
  NOTICE.txt               attribution
  THIRD_PARTY_NOTICES.md   licences of the bundled components

Install as a service (recommended)

  Open PowerShell as Administrator in this folder and run:

      powershell -ExecutionPolicy Bypass -File .\install.ps1

  Program:  C:\Program Files\Dunree\dunree.exe
  Data:     C:\ProgramData\Dunree          (conf, sys.db, log, plugins)
  Log:      C:\ProgramData\Dunree\log\service.log
  Then open http://localhost:8000 to create the admin account.

  Options:  Get-Help .\install.ps1 -Full

Manage the service (elevated prompt)

      dunree.exe service status
      dunree.exe service stop
      dunree.exe service start
      dunree.exe service uninstall
      dunree.exe service install --dir D:\Dunree -- -port=127.0.0.1:8000

Run without a service

  Copy dunree.exe into an empty folder and start it there. It keeps its data
  (conf, sys.db, log) in the folder it is started from. Stop it with Ctrl+C.

Good to know

  * Windows Firewall blocks inbound connections by default. Open the proxy ports
    with "install.ps1 -OpenFirewall" (TCP 80 and 443, UDP 443) or by hand.
  * Updates: download the new zip and run install.ps1 again. The Update page of
    the admin interface cannot replace the program on Windows.
  * The files are not code-signed. Check dunree.exe against the SHA256SUMS file
    of the release:  Get-FileHash .\dunree.exe -Algorithm SHA256
