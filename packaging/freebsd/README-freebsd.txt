Dunree for FreeBSD
==================

Dunree is a reverse proxy and web gateway, published by Foley IT under AGPL-3.0.
It is based on Zoraxy v3.3.6 by tobychui and imuslab (see NOTICE) and is an
independent project that is not endorsed by them.

Install (as root)

  install -m 755 dunree /usr/local/bin/dunree
  install -m 755 rc.d/dunree /usr/local/etc/rc.d/dunree
  sysrc dunree_enable=YES
  service dunree start

  Data: /var/db/dunree (conf, sys.db, log, plugins)     Output: /var/log/dunree.log
  Open http://<this machine>:8000 to create the admin account.

Settings in /etc/rc.conf (all optional)

  dunree_args="-port=127.0.0.1:8000"     Dunree flags, see dunree -h
  dunree_dir="/var/db/dunree"            data folder
  dunree_logfile="/var/log/dunree.log"

FreeBSD builds are provided as they are: they are compiled and checked with "go vet" for
every release, but not run or tested on FreeBSD by the project. Updates: replace
/usr/local/bin/dunree and run "service dunree restart".
