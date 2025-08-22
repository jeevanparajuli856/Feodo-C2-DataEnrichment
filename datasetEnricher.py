
# """
# datasetEnricher.py
# ------------------
# Enrich Feodo-like IOC CSVs with:
# - Geolocation & ASN (via ip-api.com batch endpoint)
# - Port service name (common port -> service; else "uncommon")
# - Derived features: first_seen/last_online as datetime, lifespan_days

# Usage:
#     python datasetEnricher.py -i input.csv -o enriched.csv

# Optional:
#     --cache ip_cache.json   # persist IP->TI responses to avoid re-querying
#     --rps 40                # requests per minute allowance for ip-api (<= 45 suggested)
#     --batch 100             # up to 100 per ip-api batch
#     --timeout 10            # HTTP timeout in seconds

# Requirements:
#     - pandas (pip install pandas)
#     - requests (pip install requests)

# Notes:
#     - ip-api.com free plan allows ~45 requests/min. We use batch POST with up to 100 IPs/request.
#     - Only unique IPs are queried. Cached entries are reused.
# """

import argparse
import json
import math
import socket
from pathlib import Path
from time import sleep
from typing import Dict, List

import pandas as pd
import requests

IP_API_URL = "http://ip-api.com/batch"  # up to 100 per request on free tier

PORT_NAME_FALLBACK = "uncommon"

def normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = (
        df.columns.str.strip()
        .str.lower()
        .str.replace(" ", "_")
        .str.replace("-", "_")
    )
    return df

def to_datetime(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ("first_seen_utc", "last_online"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    return df

def port_to_service_name(port: int, proto: str = "tcp") -> str:
    try:
        # socket.getservbyport expects an int
        return socket.getservbyport(int(port), proto)
    except Exception:
        return PORT_NAME_FALLBACK

def enrich_ports(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "dst_port" in df.columns:
        df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")
        df["dst_port_name"] = df["dst_port"].apply(lambda p: port_to_service_name(p) if pd.notna(p) else None)
    return df

def compute_lifespan(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if {"first_seen_utc", "last_online"}.issubset(df.columns):
        df["lifespan_days"] = (df["last_online"] - df["first_seen_utc"]).dt.days
    return df

def load_cache(cache_path: Path) -> Dict[str, dict]:
    if cache_path and cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_cache(cache_path: Path, cache: Dict[str, dict]) -> None:
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2),
            encoding="utf-8"   
        )

def ip_api_batch_query(ips: List[str], timeout: int = 10) -> List[dict]:
    # ip-api.com/batch accepts list of objects: {"query": "1.2.3.4"}
    payload = [{"query": ip} for ip in ips]
    resp = requests.post(IP_API_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def rate_limited_batches(items: List[str], batch_size: int, rpm: int):
    # rpm = requests per minute, sleep to respect limit
    for i in range(0, len(items), batch_size):
        chunk = items[i:i + batch_size]
        yield chunk
        # Sleep between batches except the last one
        if i + batch_size < len(items):
            sleep_time = 60.0 / max(1, rpm)
            sleep(sleep_time)

def enrich_geolocation(df: pd.DataFrame, cache_path: Path = None, rpm: int = 40, batch_size: int = 100, timeout: int = 10) -> pd.DataFrame:
    df = df.copy()
    if "dst_ip" not in df.columns:
        return df

    cache = load_cache(cache_path) if cache_path else {}

    unique_ips = sorted({ip for ip in df["dst_ip"].dropna().astype(str) if ip})
    to_query = [ip for ip in unique_ips if ip not in cache]

    # Query in batches with basic rate limiting
    for chunk in rate_limited_batches(to_query, batch_size, rpm):
        try:
            results = ip_api_batch_query(chunk, timeout=timeout)
        except Exception as e:
            # On failure, mark all with minimal info to avoid total stop; you can re-run later with cache
            results = [{"query": ip, "status": "fail", "message": str(e)} for ip in chunk]

        # Store in cache
        for res in results:
            q = res.get("query")
            if q:
                cache[q] = res

        # Persist cache after each batch
        save_cache(cache_path, cache)

    # Build columns from cache
    def map_ip(ip: str) -> dict:
        r = cache.get(str(ip), {}) if cache else {}
        return {
            "geo_status": r.get("status"),
            "country": r.get("country"),
            "country_code": r.get("countryCode"),
            "region": r.get("regionName"),
            "city": r.get("city"),
            "lat": r.get("lat"),
            "lon": r.get("lon"),
            "isp": r.get("isp"),
            "org": r.get("org"),
            "asn": r.get("as"),
            "timezone": r.get("timezone"),
        }

    geo_df = df["dst_ip"].astype(str).apply(map_ip).apply(pd.Series)
    df = pd.concat([df, geo_df], axis=1)
    return df

def main():
    ap = argparse.ArgumentParser(description="Enrich IOC CSV with IP geolocation/ASN and port names.")
    ap.add_argument("-i", "--input", required=True, help="Path to input CSV (e.g., latest_feodo_aggressive.csv)")
    ap.add_argument("-o", "--output", required=True, help="Path to write enriched CSV")
    ap.add_argument("--cache", default="data/ip_geo_cache.json", help="Path to IP enrichment cache JSON")
    ap.add_argument("--rps", type=int, default=40, help="Requests per minute for ip-api batch")
    ap.add_argument("--batch", type=int, default=100, help="Batch size for ip-api (<=100)")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    args = ap.parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    cache_path = Path(args.cache) if args.cache else None

    df = pd.read_csv(inp)

    df = normalize_cols(df)
    df = to_datetime(df)
    df = enrich_ports(df)
    df = compute_lifespan(df)
    df = enrich_geolocation(df, cache_path=cache_path, rpm=args.rps, batch_size=args.batch, timeout=args.timeout)

    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"[+] Enriched CSV saved to: {out} (rows={len(df)})")

if __name__ == "__main__":
    main()
