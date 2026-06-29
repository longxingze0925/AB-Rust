import argparse
import csv
import bisect
import ipaddress
from pathlib import Path
from typing import Any

AsnIndex = dict[int, dict[str, list[Any]]]


def read_locations(path: Path, locale: str) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}

    locations: dict[str, dict[str, str]] = {}
    country_key = f"country_name"
    subdivision_key = "subdivision_1_name"
    city_key = "city_name"

    with path.open("r", encoding="utf-8-sig", newline="") as src:
        reader = csv.DictReader(src)
        for row in reader:
            geoname_id = (row.get("geoname_id") or "").strip()
            if not geoname_id:
                continue
            country = (row.get(country_key) or row.get("country_iso_code") or "").strip()
            province = (row.get(subdivision_key) or "").strip()
            city = (row.get(city_key) or "").strip()
            locations[geoname_id] = {
                "country": country,
                "province": province,
                "city": city,
            }
    return locations


def read_asn_blocks(paths: list[Path]) -> AsnIndex:
    ranges: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8-sig", newline="") as src:
            reader = csv.DictReader(src)
            for row in reader:
                network = (row.get("network") or "").strip()
                org = (row.get("autonomous_system_organization") or "").strip()
                if not network or not org:
                    continue
                try:
                    parsed = ipaddress.ip_network(network, strict=False)
                except ValueError:
                    continue
                ranges[parsed.version].append(
                    (int(parsed.network_address), int(parsed.broadcast_address), org)
                )
    index: AsnIndex = {}
    for version, items in ranges.items():
        items.sort(key=lambda item: item[0])
        index[version] = {
            "ranges": items,
            "starts": [item[0] for item in items],
        }
    return index


def iter_city_blocks(paths: list[Path]):
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8-sig", newline="") as src:
            reader = csv.DictReader(src)
            for row in reader:
                network = (row.get("network") or "").strip()
                if not network:
                    continue
                geoname_id = (
                    row.get("geoname_id")
                    or row.get("registered_country_geoname_id")
                    or row.get("represented_country_geoname_id")
                    or ""
                ).strip()
                yield network, geoname_id


def write_geo_csv(
    out_path: Path,
    locations: dict[str, dict[str, str]],
    asn: AsnIndex,
    city_block_paths: list[Path],
    source: str,
) -> tuple[int, int]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    asn_matches = 0
    with out_path.open("w", encoding="utf-8", newline="\n") as out:
        writer = csv.DictWriter(
            out,
            fieldnames=["cidr", "country", "province", "city", "isp", "source"],
            lineterminator="\n",
        )
        writer.writeheader()
        for network, geoname_id in iter_city_blocks(city_block_paths):
            isp = lookup_asn(asn, network)
            if isp:
                asn_matches += 1
            location = locations.get(geoname_id, {})
            writer.writerow(
                {
                    "cidr": network,
                    "country": location.get("country", ""),
                    "province": location.get("province", ""),
                    "city": location.get("city", ""),
                    "isp": isp,
                    "source": source,
                }
            )
            count += 1
    return count, asn_matches


def lookup_asn(asn: AsnIndex, network: str) -> str:
    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return ""

    data = asn.get(parsed.version, {})
    ranges = data.get("ranges", [])
    starts = data.get("starts", [])
    if not ranges:
        return ""

    start = int(parsed.network_address)
    end = int(parsed.broadcast_address)
    index = bisect.bisect_right(starts, start) - 1
    while index >= 0:
        range_start, range_end, org = ranges[index]
        if range_end < start:
            break
        if range_start <= start and range_end >= end:
            return org
        index -= 1
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert MaxMind GeoLite2/GeoIP2 CSV files to the local ip_geo CSV format."
    )
    parser.add_argument(
        "--city-dir",
        required=True,
        help="Directory containing GeoLite2-City-Blocks-*.csv and GeoLite2-City-Locations-*.csv",
    )
    parser.add_argument(
        "--asn-dir",
        default="",
        help="Directory containing GeoLite2-ASN-Blocks-*.csv. Optional.",
    )
    parser.add_argument("--out", required=True, help="Output local ip_geo CSV file")
    parser.add_argument("--locale", default="en", help="MaxMind locations locale, default: en")
    parser.add_argument("--source", default="maxmind", help="Source label written to CSV")
    args = parser.parse_args()

    city_dir = Path(args.city_dir)
    asn_dir = Path(args.asn_dir) if args.asn_dir else Path()
    out_path = Path(args.out)

    locations = read_locations(
        city_dir / f"GeoLite2-City-Locations-{args.locale}.csv",
        args.locale,
    )
    if not locations and args.locale != "en":
        locations = read_locations(city_dir / "GeoLite2-City-Locations-en.csv", "en")

    asn = read_asn_blocks(
        [
            asn_dir / "GeoLite2-ASN-Blocks-IPv4.csv",
            asn_dir / "GeoLite2-ASN-Blocks-IPv6.csv",
        ]
    )
    count, asn_matches = write_geo_csv(
        out_path,
        locations,
        asn,
        [
            city_dir / "GeoLite2-City-Blocks-IPv4.csv",
            city_dir / "GeoLite2-City-Blocks-IPv6.csv",
        ],
        args.source,
    )
    print(f"Wrote {count} MaxMind ranges to {out_path}; ASN matched {asn_matches}")


if __name__ == "__main__":
    main()
