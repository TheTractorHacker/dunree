Dunree for macOS
================

Dunree is a reverse proxy and web gateway, published by Foley IT under AGPL-3.0.
It is based on Zoraxy v3.3.6 by tobychui and imuslab (see NOTICE) and is an
independent project that is not endorsed by them.

Contents of this folder

  dunree                     the program for this CPU (amd64 = Intel, arm64 = Apple silicon)
  ie.foleyit.dunree.plist    launchd job (starts Dunree at boot, restarts it after a crash)
  uninstall.sh               removes an install made as described below
  LICENSE, NOTICE, THIRD_PARTY_NOTICES.md

Try it

  mkdir ~/dunree && cp dunree ~/dunree/ && cd ~/dunree && ./dunree
  Open http://localhost:8000. Stop with Ctrl+C. The data stays in ~/dunree.
  The program is not signed with an Apple developer certificate. If macOS refuses to
  start a downloaded copy:  xattr -d com.apple.quarantine ./dunree

Install as a system service (ports 80 and 443 need root)

  sudo mkdir -p /usr/local/bin /usr/local/var/dunree /usr/local/var/log/dunree
  sudo chmod 750 /usr/local/var/dunree
  sudo cp dunree /usr/local/bin/dunree
  sudo cp ie.foleyit.dunree.plist /Library/LaunchDaemons/
  sudo chown root:wheel /Library/LaunchDaemons/ie.foleyit.dunree.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/ie.foleyit.dunree.plist

  Data: /usr/local/var/dunree        Log: /usr/local/var/log/dunree/dunree.log
  Stop:    sudo launchctl bootout system/ie.foleyit.dunree
  Restart: sudo launchctl kickstart -k system/ie.foleyit.dunree

Updates: replace /usr/local/bin/dunree with the new program and restart the job. The Update
page of the admin interface only installs Linux builds.
