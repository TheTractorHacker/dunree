#!/usr/bin/env python3

import os
import shutil
import signal
import subprocess
import sys
import time

dunree_proc = None
zerotier_proc = None

def getenv(key, default=None):
  return os.environ.get(key, default)

# The Dunree image keeps everything under /opt/dunree (with /opt/zoraxy as a link to it) and the
# program as dunree. An image built from an older Dockerfile only has /opt/zoraxy and zoraxy;
# both layouts work. # legacy-compat
def base_dir(exists=os.path.isdir):
  return "/opt/dunree" if exists("/opt/dunree") else "/opt/zoraxy"

def program(which=shutil.which):
  return "dunree" if which("dunree") else "zoraxy"

def run(command):
  try:
    subprocess.run(command, check=True)
  except subprocess.CalledProcessError as e:
    print(f"Command failed: {command} - {e}")
    sys.exit(1)

def popen(command):
  proc = subprocess.Popen(command)
  time.sleep(1)
  # Check for early exits which may indicate crashes or other failures
  if proc.poll() is not None:
    print(f"{command} exited early with code {proc.returncode}")
    raise RuntimeError(f"Failed to start {command}")
  return proc

def cleanup(_signum, _frame):
  print("Shutdown signal received. Cleaning up...")

  global dunree_proc, zerotier_proc

  if dunree_proc and dunree_proc.poll() is None:
    print("Terminating Dunree...")
    dunree_proc.terminate()

  if zerotier_proc and zerotier_proc.poll() is None:
    print("Terminating ZeroTier-One...")
    zerotier_proc.terminate()

  # Wait for Dunree and ZeroTier to cleanly exit
  if dunree_proc:
    try:
      dunree_proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
      dunree_proc.kill()
      dunree_proc.wait()

  if zerotier_proc:
    try:
      zerotier_proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
      zerotier_proc.kill()
      zerotier_proc.wait()

  try:
    os.unlink("/var/lib/zerotier-one")
  except FileNotFoundError:
    pass
  except Exception as e:
    print(f"Failed to unlink ZeroTier socket: {e}")

  sys.exit(0)

def start_zerotier():
  print("Starting ZeroTier...")

  global zerotier_proc

  config_dir = base_dir() + "/config/zerotier/"
  zt_path = "/var/lib/zerotier-one"

  os.makedirs(config_dir, exist_ok=True)

  # Symlink the host mount to the ZeroTier config path
  try:
    os.symlink(config_dir, zt_path, target_is_directory=True)
  except FileExistsError:
    print(f"Symlink {zt_path} already exists, skipping creation.")

  zerotier_proc = popen(["zerotier-one"])

def start_dunree():
  print("Starting Dunree...")

  global dunree_proc

  dunree_args = [
    program(),
    f"-autorenew={ getenv('AUTORENEW', '86400') }",
    f"-cfgupgrade={ getenv('CFGUPGRADE', 'true') }",
    f"-db={ getenv('DB', 'auto') }",
    f"-docker={ getenv('DOCKER', 'true') }",
    f"-earlyrenew={ getenv('EARLYRENEW', '30') }",
    f"-enablelog={ getenv('ENABLELOG', 'true') }",
    f"-fastgeoip={ getenv('FASTGEOIP', 'false') }",
    f"-mdns={ getenv('MDNS', 'true') }",
    f"-mdnsname={ getenv('MDNSNAME', "''") }",
    f"-noauth={ getenv('NOAUTH', 'false') }",
    f"-plugin={ getenv('PLUGIN', base_dir() + '/plugin/') }",
    f"-port=:{ getenv('PORT', '8000') }",
    f"-sshlb={ getenv('SSHLB', 'false') }",
    f"-version={ getenv('VERSION', 'false') }",
    f"-webroot={ getenv('WEBROOT', './www') }",
  ]

  dunree_proc = popen(dunree_args)

def main():
  # Register signal handlers to allow clean shutdowns
  signal.signal(signal.SIGTERM, cleanup)
  signal.signal(signal.SIGINT, cleanup)

  print("Updating CA certificates...")
  run(["update-ca-certificates"])

  if getenv("UPDATE_GEOIP", "false").lower() == "true":
    print("Updating GeoIP data...")
    run([program(), "-update_geoip=true"])

  os.chdir(base_dir() + "/config/")

  if getenv("ZEROTIER", "false") == "true":
    start_zerotier()

  start_dunree()

  signal.pause()

if __name__ == "__main__":
  main()

