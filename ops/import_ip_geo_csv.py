import argparse
import csv
from pathlib import Path


def sql_string(value: str) -> str:
    return "'" + (value or "").replace("'", "''") + "'"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate PostgreSQL upsert SQL for ip_geo_ranges from a CSV file."
    )
    parser.add_argument("--csv", required=True, help="CSV file path")
    parser.add_argument("--out", required=True, help="Output SQL file path")
    parser.add_argument(
        "--source",
        default="csv",
        help="Default source when the CSV has no source column",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as src, out_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as out:
        reader = csv.DictReader(src)
        required = {"cidr", "country"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"CSV missing required columns: {', '.join(sorted(missing))}")

        out.write("BEGIN;\n")
        for row in reader:
            cidr = (row.get("cidr") or "").strip()
            if not cidr:
                continue
            country = (row.get("country") or "").strip()
            province = (row.get("province") or "").strip()
            city = (row.get("city") or "").strip()
            isp = (row.get("isp") or "").strip()
            source = (row.get("source") or args.source).strip()
            out.write(
                "INSERT INTO ip_geo_ranges (cidr, country, province, city, isp, source) "
                f"VALUES ({sql_string(cidr)}::cidr, {sql_string(country)}, "
                f"{sql_string(province)}, {sql_string(city)}, {sql_string(isp)}, "
                f"{sql_string(source)}) "
                "ON CONFLICT (cidr) DO UPDATE SET "
                "country = EXCLUDED.country, "
                "province = EXCLUDED.province, "
                "city = EXCLUDED.city, "
                "isp = EXCLUDED.isp, "
                "source = EXCLUDED.source, "
                "updated_at = now();\n"
            )
            count += 1
        out.write("COMMIT;\n")

    print(f"Wrote {count} IP geo ranges to {out_path}")


if __name__ == "__main__":
    main()
