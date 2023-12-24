import sys
import subprocess
from config import *

def eprint(s):
    print(s, file=sys.stderr)

def bail(s):
    eprint(s)
    exit(1)

def map_to_id(x): 
    return list(map(lambda y: y.id, x))

def build_binary(filepath):
    try:
        subprocess.run(f"nix --extra-experimental-features 'nix-command flakes' bundle .. -o {filepath}",
                       capture_output=True,
                       shell=True,
                       check=True)
        return subprocess.run(f"sha256sum {filepath}", shell=True, capture_output=True, check=True).stdout.decode("ascii").split(" ")[0]
    except subprocess.CalledProcessError as e:
        bail(f"Bundling binary failed with exit code {e.returncode}:\n{e.stdout}\n{e.stderr}")

def build_pkg(filepath):
    pkg_path = f"{filepath}/{PKG_NAME}"
    try:
        subprocess.run(f"nix --extra-experimental-features 'nix-command flakes' bundle --bundler github:NixOS/bundlers#toRPM .. -o {filepath}",
                       capture_output=True,
                       shell=True,
                       check=True)
        return (pkg_path, subprocess.run(f"sha256sum {pkg_path}", shell=True, capture_output=True, check=True).stdout.decode("ascii").split(" ")[0])
    except subprocess.CalledProcessError as e:
        bail(f"Bundling binary failed with exit code {e.returncode}:\n{e.stdout}\n{e.stderr}")
