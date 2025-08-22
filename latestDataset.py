
# """
# latestDataset.py
# ----------------
# Fetch the latest aggressive Feodo Tracker IP blocklist as CSV.

# Usage:
#     python latestDataset.py [-o OUTPUT_PATH]

# Notes:
# - Saves to ./data/ by default with a timestamped filename and a stable symlink 'latest_feodo_aggressive.csv'.
# - Requires internet access to fetch from: https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv
# """

import argparse
import datetime as dt
from pathlib import Path
import sys
import urllib.request

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv" #getting all block c2 server list 

#This is the function to download the lastest dataset from feodotracker site which will use later to visualize the c2 block ip server.
def download_file(url: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url) as resp:
            data = resp.read()
        out_path.write_bytes(data)
        return out_path
    except Exception as e:
        print(f"[!] Download failed: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Download latest Feodo Tracker aggressive IP blocklist CSV.")
    parser.add_argument("-o", "--output", default=None, help="Output CSV path. Defaults to ./data/feodo_aggressive_YYYYMMDD.csv")
    args = parser.parse_args()

    if args.output:
        out_path = Path(args.output)
    else:
        today = dt.datetime.now(dt.UTC).strftime("%Y%m%d")
        out_path = Path("data") / f"feodo_aggressive_{today}.csv"

    saved = download_file(URL, out_path)
    print(f"\nDownloading latest dataset............./")
    print(f"[+] Saved: {saved} ({saved.stat().st_size} bytes)\n")

    # Maintain a stable "latest" file for downstream pipelines
    latest = saved.parent / "latest_feodo_aggressive.csv"
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        try:
            latest.symlink_to(saved.name)  # relative symlink inside the same dir
        except (AttributeError, NotImplementedError, OSError):
            # On Windows or restricted FS, fall back to copying
            latest.write_bytes(saved.read_bytes())
        print(f"[+] Updated: {latest}\n")
    except Exception as e:
        print(f"[!] Could not update latest pointer: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
