#!/usr/bin/env python3
"""TrackerIp - one-file location toolkit for CTF.

Subcommands:
ip   <addr...>            IP geolocation
exif <image...>           extract GPS from EXIF metadata
wifi <bssid...>           WiFi BSSID lookup
cell <mcc,mnc,lac,cid>    cell tower lookup
auto <target...>          auto-detect input type

All providers are free (no API key). Only Python stdlib used.
"""
import argparse
import json
import os
import re
import struct
import sys
import urllib.request
from contextlib import contextmanager

TIMEOUT = 15
UA = {"User-Agent": "locate-ctf/1.0"}
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(SCRIPT_DIR, "out")


# helpers


def http_json(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())


def maps_url(lat, lon):
    return f"https://maps.google.com/?q={lat},{lon}"


def reverse_geocode(lat, lon):
    try:
        url = (f"https://nominatim.openstreetmap.org/reverse"
                f"?format=json&lat={lat}&lon={lon}&zoom=16")
        d = http_json(url)
        return d.get("display_name", "")
    except Exception:
        return ""


def sanitize(name):
    return re.sub(r"[^\w.\-]+", "_", name)


PREFIX = ""

@contextmanager
def tee_output(subdir, fname):
    sub = sanitize(subdir)
    if PREFIX:
        sub = f"{PREFIX}_{sub}"
    d = os.path.join(OUT_DIR, sub)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, fname)
    old = sys.stdout

    class _Tee:
        def write(self, s):
            old.write(s)
            fh.write(s)

        def flush(self):
            old.flush()
            fh.flush()

    with open(path, "w", encoding="utf-8") as fh:
        sys.stdout = _Tee()
        try:
            yield path
        finally:
            sys.stdout = old



# IP geolocation


def cmd_ip(args):
    ips = []
    for a in args.addr:
        if a.startswith("@"):
            with open(a[1:]) as fh:
                ips += [l.strip() for l in fh if l.strip()]
        else:
            ips.append(a)
    provider = getattr(args, "provider", "ipapi")
    for ip in ips:
        with tee_output(ip, "ip.txt") as out:
            print(f"[{ip}] saved -> {out}")
            try:
                if provider == "ipinfo":
                    url = f"https://ipinfo.io/{ip}/json"
                    headers = dict(UA)
                    token = getattr(args, "token", None)
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                        d = json.loads(r.read().decode())
                    if getattr(args, "json", False):
                        print(json.dumps(d, indent=2))
                        continue
                    print(f"[{ip}] {d.get('ip')}")
                    for k in ("city", "region", "country", "postal",
                                "loc", "org", "timezone"):
                        if d.get(k):
                            print(f"  {k:<12}: {d[k]}")
                    if d.get("loc"):
                        lat, lon = d["loc"].split(",")
                        print(f"  {'map':<12}: {maps_url(lat, lon)}")
                    continue
                url = (f"http://ip-api.com/json/{ip}"
                        "?fields=status,message,country,regionName,city,zip,"
                        "lat,lon,timezone,isp,org,as,reverse")
                d = http_json(url)
                if d.get("status") == "fail":
                    print(f"[{ip}] ERROR: {d.get('message')}")
                    continue
                if getattr(args, "json", False):
                    print(json.dumps(d, indent=2))
                    continue
                print(f"[{ip}] {d.get('reverse') or d.get('query')}")
                for k in ("country", "regionName", "city", "zip",
                            "lat", "lon", "timezone", "isp", "org", "as"):
                    if d.get(k):
                        print(f"  {k:<12}: {d[k]}")
                print(f"  {'map':<12}: {maps_url(d['lat'], d['lon'])}")
            except Exception as e:
                print(f"[{ip}] LOOKUP FAILED: {e}", file=sys.stderr)



# EXIF GPS extraction (pure stdlib, no PIL needed)


TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 9: 4, 10: 8}
GPS_TAGS = {1: "LatRef", 2: "Lat", 3: "LonRef", 4: "Lon", 5: "AltRef",
            6: "Alt", 7: "TimeStamp", 29: "DateStamp"}


def exif_tiff(data):
    """Return (byte_order_char, tiff_base) if data starts with a TIFF header."""
    if len(data) < 8:
        return None
    if data[:2] == b"II":
        order = "<"
    elif data[:2] == b"MM":
        order = ">"
    else:
        return None
    if struct.unpack(order + "H", data[2:4])[0] != 0x2A:
        return None
    return order, 0


def read_ifd(data, order, base, offset):
    if offset == 0 or offset + 2 > len(data):
        return {}
    count = struct.unpack_from(order + "H", data, base + offset)[0]
    pos = base + offset + 2
    entries = []
    for _ in range(count):
        if pos + 12 > len(data):
            break
        tag, typ, cnt = struct.unpack_from(order + "HHI", data, pos)
        entries.append((tag, typ, cnt, data[pos + 8:pos + 12]))
        pos += 12
    return entries


def ifd_value(data, order, base, entry):
    tag, typ, cnt, raw = entry
    size = TYPE_SIZE.get(typ, 1) * cnt
    if size <= 4:
        buf = raw
    else:
        off = struct.unpack_from(order + "I", raw, 0)[0]
        buf = data[base + off:base + off + size]
    if typ == 2:
        return buf.split(b"\0")[0].decode("utf-8", "replace")
    if typ == 5 or typ == 10:
        if cnt == 3:
            vals = []
            for i in range(3):
                n, d = struct.unpack_from(order + "ii", buf, i * 8)
                vals.append(n / d if d else 0)
            return vals
        n, d = struct.unpack_from(order + "ii", buf, 0)
        return n / d if d else 0
    fmt = {1: "B", 3: "H", 4: "I", 6: "b", 9: "i"}.get(typ)
    if not fmt:
        return None
    if cnt == 1:
        return struct.unpack_from(order + fmt, buf, 0)[0]
    return list(struct.unpack_from(order + fmt * cnt, buf, 0))


def dms_to_decimal(dms, ref):
    if not dms or len(dms) != 3:
        return None
    dec = dms[0] + dms[1] / 60 + dms[2] / 3600
    if ref in ("S", "W"):
        dec = -dec
    return dec


def cmd_exif(args):
    for path in args.image:
        name = os.path.splitext(os.path.basename(path))[0]
        with tee_output(name, "exif.txt") as out:
            print(f"[{path}] saved -> {out}")
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                print(f"[{path}] READ FAILED: {e}", file=sys.stderr)
                continue

            tiff = None
            pos = 0
            while pos < len(data) - 4:
                if data[pos:pos + 2] == b"\xff\xe1" and data[pos + 4:pos + 8] == b"Exif":
                    size = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                    tiff = exif_tiff(data[pos + 10:pos + 4 + size])
                    if tiff:
                        base_abs = pos + 10
                        break
                pos += 1

            if not tiff:
                print(f"[{path}] no EXIF/GPS metadata found")
                continue

            order, base = tiff
            ifd0 = read_ifd(data, order, base_abs, struct.unpack_from(order + "I", data, base_abs + 4)[0])
            ifd0_map = dict((t, (ty, c, r)) for (t, ty, c, r) in ifd0)

            exif_off = None
            gps_off = None
            for e in ifd0:
                if e[0] == 0x8769:
                    exif_off = struct.unpack_from(order + "I", e[3], 0)[0]
                if e[0] == 0x8825:
                    gps_off = struct.unpack_from(order + "I", e[3], 0)[0]

            gps = {}
            if exif_off:
                for e in read_ifd(data, order, base_abs, exif_off):
                    if e[0] == 0x8825:
                        gps_off = struct.unpack_from(order + "I", e[3], 0)[0]

            if gps_off:
                for e in read_ifd(data, order, base_abs, gps_off):
                    gps[e[0]] = ifd_value(data, order, base_abs, e)

            lat = dms_to_decimal(gps.get(2), gps.get(1))
            lon = dms_to_decimal(gps.get(4), gps.get(3))

            print(f"[{path}]")
            if lat is None or lon is None:
                print("  no GPS coordinates in EXIF")
                continue
            print(f"  {'lat':<12}: {lat}")
            print(f"  {'lon':<12}: {lon}")
            print(f"  {'map':<12}: {maps_url(lat, lon)}")
            addr = reverse_geocode(lat, lon)
            if addr:
                print(f"  {'address':<12}: {addr}")



# WiFi / cell lookup

def _beacondb(payload):
    req = urllib.request.Request(
        "https://api.beacondb.net/v1/geolocate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())




def _pb_varint(data, i):
    shift = 0
    val = 0
    while True:
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def _pb_fields(buf):
    out = []
    i = 0
    while i < len(buf):
        key, i = _pb_varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _pb_varint(buf, i)
            out.append((fn, 0, v))
        elif wt == 2:
            ln, i = _pb_varint(buf, i)
            out.append((fn, 2, buf[i:i + ln]))
            i += ln
        elif wt == 1:
            out.append((fn, 1, buf[i:i + 8]))
            i += 8
        else:
            break
    return out


def _pb_enc_varint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        out += bytes([b | (0x80 if v else 0)])
        if not v:
            return out


def _s64(v):
    if v >= (1 << 63):
        v -= (1 << 64)
    return v


def _apple_wloc(bssids):
    """Query Apple's WiFi geolocation API. Returns {bssid: (lat, lon, acc)}."""
    inner = []
    for bssid in bssids:
        mac = bssid.encode()
        dev = b"\x0a" + _pb_enc_varint(len(mac)) + mac         
        inner.append(b"\x12" + _pb_enc_varint(len(dev)) + dev)  
    msg = b"".join(inner) + b"\x20\x01"                          
    header = (b"\x00\x01\x00\x05" + b"en_US" + b"\x00\x13" +
                b"com.apple.locationd" + b"\x00\x0a" + b"8.1.12B411" +
                b"\x00\x00\x00\x01\x00\x00\x00" + bytes([len(msg)]) + msg)
    req = urllib.request.Request(
        "https://gs-loc.apple.com/clls/wloc",
        data=header,
        headers={"User-Agent": "locationd/1753.17 CFNetwork/889.9 Darwin/17.2.0"})
    resp = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    results = {}
    for fn, wt, v in _pb_fields(resp[10:]):
        if fn != 2:
            continue
        bssid = None
        loc = None
        for f2, w2, v2 in _pb_fields(v):
            if f2 == 1:
                bssid = v2.decode().lower()
            elif f2 == 2:
                fields = dict((f3, v3) for f3, w3, v3 in _pb_fields(v2))
                loc = (_s64(fields.get(1, 0)) / 1e8,
                        _s64(fields.get(2, 0)) / 1e8,
                        fields.get(3))
        if bssid and loc:
            results[bssid] = loc
    return results


def cmd_wifi(args):
    for bssid in args.bssid:
        mac = bssid.replace(":", "").replace("-", "").lower()
        if not re.fullmatch(r"[0-9a-f]{12}", mac):
            print(f"[{bssid}] invalid BSSID")
            continue
        with tee_output(bssid, "wifi.txt") as out:
            print(f"[{bssid}] saved -> {out}")
            hit = False
            try:
                for b, (lat, lon, acc) in _apple_wloc([bssid]).items():
                    if b.replace(":", "").replace("-", "") == mac:
                        print(f"[{bssid}] lat={lat} lon={lon} (Apple)")
                        print(f"  {'map':<12}: {maps_url(lat, lon)}")
                        print(f"  {'accuracy(m)':<12}: {acc}")
                        hit = True
                        break
            except Exception:
                pass
            if hit:
                continue
            try:
                d = http_json(f"http://api.mylnikov.org/wifi?v=1.1&bssid={mac}")
                if str(d.get("result")) == "ok":
                    lat, lon = d["data"]["lat"], d["data"]["lon"]
                    print(f"[{bssid}] lat={lat} lon={lon}")
                    print(f"  {'map':<12}: {maps_url(lat, lon)}")
                    print(f"  {'range(m)':<12}: {d['data'].get('range', '?')}")
                    continue
            except Exception:
                pass
            try:
                d = _beacondb({"wifiAccessPoints": [{"macAddress": bssid}]})
                loc = d.get("location")
                if loc:
                    lat, lon = loc["lat"], loc["lng"]
                    note = " (IP fallback)" if d.get("fallback") else ""
                    print(f"[{bssid}] lat={lat} lon={lon}{note}")
                    print(f"  {'map':<12}: {maps_url(lat, lon)}")
                    print(f"  {'accuracy(m)':<12}: {d.get('accuracy', '?')}")
                else:
                    print(f"[{bssid}] not found in database")
            except Exception as e:
                print(f"[{bssid}] LOOKUP FAILED: {e}", file=sys.stderr)


def cmd_cell(args):
    try:
        mcc, mnc, lac, cid = [int(x) for x in args.lac_cell.split(",")]
    except ValueError:
        print("usage: TrackerIp cell mcc,mnc,lac,cellid   e.g. 510,10,12345,6789")
        return
    with tee_output(f"{mcc}-{mnc}-{lac}-{cid}", "cell.txt") as out:
        print(f"[{mcc}/{mnc} LAC {lac} CID {cid}] saved -> {out}")
        try:
            d = http_json(f"http://api.mylnikov.org/geolocation/v1.1/cell?"
                        f"v=1.1&mcc={mcc}&mnc={mnc}&lac={lac}&cellid={cid}")
            if str(d.get("result")) == "ok":
                lat, lon = d["data"]["lat"], d["data"]["lon"]
                print(f"[{mcc}/{mnc} LAC {lac} CID {cid}]")
                print(f"  {'lat':<12}: {lat}")
                print(f"  {'lon':<12}: {lon}")
                print(f"  {'map':<12}: {maps_url(lat, lon)}")
                print(f"  {'range(m)':<12}: {d['data'].get('range', '?')}")
            else:
                print("cell tower not found in database")
        except Exception:
            try:
                d = _beacondb({"cellTowers": [{
                    "mobileCountryCode": mcc, "mobileNetworkCode": mnc,
                    "locationAreaCode": lac, "cellId": cid}]})
                loc = d.get("location")
                if loc:
                    lat, lon = loc["lat"], loc["lng"]
                    print(f"[{mcc}/{mnc} LAC {lac} CID {cid}]")
                    print(f"  {'lat':<12}: {lat}")
                    print(f"  {'lon':<12}: {lon}")
                    print(f"  {'map':<12}: {maps_url(lat, lon)}")
                    print(f"  {'accuracy(m)':<12}: {d.get('accuracy', '?')}")
                else:
                    print("cell tower not found in database")
            except Exception as e:
                print(f"LOOKUP FAILED: {e}", file=sys.stderr)



# auto mode


def cmd_auto(args):
    for target in args.target:
        t = target.strip()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t):
            print(f"--- {t} as IP ---")
            cmd_ip(type("A", (), {"addr": [t]})())
        elif re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", t):
            print(f"--- {t} as BSSID ---")
            cmd_wifi(type("A", (), {"bssid": [t]})())
        elif t.count(",") == 3:
            print(f"--- {t} as cell tower ---")
            cmd_cell(type("A", (), {"lac_cell": t})())
        elif t.lower().endswith((".jpg", ".jpeg", ".png", ".tiff", ".heic", ".webp")):
            print(f"--- {t} as image ---")
            cmd_exif(type("A", (), {"image": [t]})())
        else:
            print(f"--- {t} : could not auto-detect ---")




def interactive_menu():
    RED = "\033[0;31m"; GREEN = "\033[0;32m"; YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"; NC = "\033[0m"
    BAN = "\033[38;2;31;255;170m"

    banner = [
        "████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ ██╗██████╗",
        "╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██║██╔══██╗",
        "   ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝██║██████╔╝",
        "   ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║██╔═══╝",
        "   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║██║██║",
        "   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝",
    ]
    for line in banner:
        print(f"{BAN}{line}{NC}")
    print(f"{BAN}             one-file location toolkit (CTF)          {NC}")
    print()

    global PREFIX
    while True:
        print(f"{BAN}----------------------------------------{NC}")
        print("  1) IP geolocation            (ip-api / ipinfo)")
        print("  2) GPS dari EXIF foto")
        print("  3) WiFi BSSID lookup")
        print("  4) Cell tower (BTS) lookup")
        print("  5) Auto-detect input")
        print("  0) Keluar")
        print(f"{BAN}----------------------------------------{NC}")
        pilih = input("Pilih nomor: ").strip()

        if pilih == "0":
            PREFIX = ""
            print(f"{GREEN}[OK]{NC} Sampai jumpa!")
            break
        elif pilih == "1":
            PREFIX = "1_ip"
            val = input(f"{CYAN}[>]{NC} Masukkan IP (pisah spasi, atau @file): ").strip()
            if val:
                cmd_ip(type("A", (), {"addr": val.split()})())
        elif pilih == "2":
            PREFIX = "2_exif"
            val = input(f"{CYAN}[>]{NC} Masukkan path foto (pisah spasi): ").strip()
            if val:
                cmd_exif(type("A", (), {"image": val.split()})())
        elif pilih == "3":
            PREFIX = "3_wifi"
            val = input(f"{CYAN}[>]{NC} Masukkan BSSID (contoh: aa:bb:cc:dd:ee:ff): ").strip()
            if val:
                cmd_wifi(type("A", (), {"bssid": val.split()})())
        elif pilih == "4":
            PREFIX = "4_cell"
            val = input(f"{CYAN}[>]{NC} Masukkan mcc,mnc,lac,cellid (contoh: 510,10,12345,6789): ").strip()
            if val:
                cmd_cell(type("A", (), {"lac_cell": val})())
        elif pilih == "5":
            PREFIX = "5_auto"
            val = input(f"{CYAN}[>]{NC} Masukkan target (pisah spasi): ").strip()
            if val:
                cmd_auto(type("A", (), {"target": val.split()})())
        else:
            PREFIX = ""
            print(f"{RED}[X]{NC} Angka tidak valid.")
        print()


def main():
    if len(sys.argv) < 2 or "-m" in sys.argv or "--menu" in sys.argv:
        interactive_menu()
        return
    ap = argparse.ArgumentParser(description="TrackerIp - one-file location toolkit (CTF)")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("ip", help="IP geolocation")
    p.add_argument("addr", nargs="+", help="IPs, or @file for a list")
    p.add_argument("-p", "--provider", choices=["ipapi", "ipinfo"],
                    default="ipapi", help="provider (default: ipapi)")
    p.add_argument("-t", "--token", help="token for ipinfo provider (optional)")
    p.add_argument("-j", "--json", action="store_true",
                    help="raw JSON output")
    p.set_defaults(func=cmd_ip)

    p = sub.add_parser("exif", help="extract GPS from image EXIF")
    p.add_argument("image", nargs="+")
    p.set_defaults(func=cmd_exif)

    p = sub.add_parser("wifi", help="WiFi BSSID lookup")
    p.add_argument("bssid", nargs="+", help="e.g. aa:bb:cc:dd:ee:ff")
    p.set_defaults(func=cmd_wifi)

    p = sub.add_parser("cell", help="cell tower lookup")
    p.add_argument("lac_cell", help="mcc,mnc,lac,cellid")
    p.set_defaults(func=cmd_cell)

    p = sub.add_parser("auto", help="auto-detect input type")
    p.add_argument("target", nargs="+")
    p.set_defaults(func=cmd_auto)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()