#!/usr/bin/env python3
import argparse
import datetime as dt
import os
import re
import sqlite3
import sys
import uuid
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert legacy Next.js SQLite data into PostgreSQL SQL for the Rust backend."
    )
    parser.add_argument("--sqlite", required=True, help="Path to old app.db")
    parser.add_argument("--out", required=True, help="Output .sql path")
    args = parser.parse_args()

    db_path = Path(args.sqlite)
    if not db_path.exists():
        raise SystemExit(f"SQLite file not found: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    route_map: dict[int, str] = {}
    template_map: dict[int, str] = {}
    promo_map: dict[int, str] = {}
    visit_map: dict[int, str] = {}

    statements: list[str] = [
        "BEGIN;",
        "SET CONSTRAINTS ALL DEFERRED;",
    ]

    for row in rows(conn, "landing_templates"):
        new_id = new_uuid()
        template_map[int(row["id"])] = new_id
        statements.append(
            insert(
                "landing_templates",
                {
                    "id": new_id,
                    "name": text(row, "name"),
                    "storage_key": text(row, "storage_key"),
                    "entry_file": text(row, "entry_file", "index.html"),
                    "file_count": int_value(row, "file_count"),
                    "size_bytes": int_value(row, "size_bytes"),
                    "created_at": timestamp(row, "created_at"),
                },
            )
        )

    for row in rows(conn, "landing_routes"):
        route_id = new_uuid()
        legacy_id = int(row["id"])
        route_map[legacy_id] = route_id
        target_type = text(row, "real_target_type", "internal")
        if target_type != "external":
            target_type = "internal"
        landing_mode = text(row, "landing_mode", "default")
        if landing_mode != "template":
            landing_mode = "default"
        template_id = template_map.get(int_value(row, "landing_template_id")) if landing_mode == "template" else None
        if landing_mode == "template" and template_id is None:
            landing_mode = "default"

        statements.extend(
            [
                insert(
                    "routes",
                    {
                        "id": route_id,
                        "name": text(row, "name"),
                        "entry_domain": clean_domain(text(row, "entry_domain")),
                        "enabled": bool_int(row, "enabled", 1),
                        "created_at": timestamp(row, "created_at"),
                        "updated_at": timestamp(row, "updated_at"),
                    },
                ),
                insert(
                    "route_targets",
                    {
                        "route_id": route_id,
                        "target_type": target_type,
                        "exit_domain": clean_domain(text(row, "exit_domain")) if target_type == "internal" else None,
                        "external_url": text(row, "external_url") if target_type == "external" else "",
                    },
                ),
                insert(
                    "route_landing_configs",
                    {
                        "route_id": route_id,
                        "landing_mode": landing_mode,
                        "template_id": template_id,
                        "title": text(row, "title", "下载"),
                        "image_asset_id": None,
                        "apk_url": text(row, "apk_url"),
                        "auto_download": bool_int(row, "auto_download", 1),
                    },
                ),
                insert(
                    "route_cloak_configs",
                    {
                        "route_id": route_id,
                        "enabled": bool_int(row, "cloak_enabled"),
                        "threshold": int_value(row, "cloak_threshold", 8),
                        "token_hours": int_value(row, "cloak_token_hours", 6),
                        "decoy_title": text(row, "cloak_decoy_title", "下载"),
                        "decoy_apk_url": text(row, "cloak_decoy_apk_url"),
                    },
                ),
                insert(
                    "route_meta_configs",
                    {
                        "route_id": route_id,
                        "enabled": bool_int(row, "meta_enabled"),
                        "pixel_id": text(row, "meta_pixel_id"),
                        "capi_token": text(row, "meta_capi_token"),
                        "test_event_code": text(row, "meta_test_event_code"),
                        "currency": text(row, "meta_currency", "USD").upper(),
                        "value": number_value(row, "meta_value"),
                        "page_view_enabled": bool_int(row, "meta_page_view_enabled", 1),
                        "view_content_enabled": bool_int(row, "meta_view_content_enabled", 1),
                        "lead_enabled": bool_int(row, "meta_lead_enabled", 1),
                    },
                ),
                allowlist(clean_domain(text(row, "entry_domain"))),
            ]
        )
        if target_type == "internal":
            statements.append(allowlist(clean_domain(text(row, "exit_domain"))))

    # Legacy deployments before landing_routes used current entry/exit domains plus global settings.
    if not route_map and has_table(conn, "entry_domains") and has_table(conn, "exit_domains"):
        entry = first_current(conn, "entry_domains")
        exit_ = first_current(conn, "exit_domains")
        if entry and exit_:
            route_id = new_uuid()
            route_map[0] = route_id
            settings = {r["key"]: r["value"] for r in rows(conn, "settings")}
            statements.extend(
                [
                    insert(
                        "routes",
                        {
                            "id": route_id,
                            "name": "legacy-default",
                            "entry_domain": clean_domain(entry["domain"]),
                            "enabled": True,
                            "created_at": now(),
                            "updated_at": now(),
                        },
                    ),
                    insert(
                        "route_targets",
                        {
                            "route_id": route_id,
                            "target_type": "internal",
                            "exit_domain": clean_domain(exit_["domain"]),
                            "external_url": "",
                        },
                    ),
                    insert(
                        "route_landing_configs",
                        {
                            "route_id": route_id,
                            "landing_mode": "default",
                            "template_id": None,
                            "title": settings.get("title") or "下载",
                            "image_asset_id": None,
                            "apk_url": settings.get("apk_url") or "",
                            "auto_download": settings.get("auto_download", "1") != "0",
                        },
                    ),
                    insert("route_cloak_configs", {"route_id": route_id}),
                    insert("route_meta_configs", {"route_id": route_id}),
                    allowlist(clean_domain(entry["domain"])),
                    allowlist(clean_domain(exit_["domain"])),
                ]
            )

    for row in rows(conn, "promo_codes"):
        promo_id = new_uuid()
        legacy_id = int(row["id"])
        promo_map[legacy_id] = promo_id
        route_id = route_map.get(int_value(row, "route_id")) or route_map.get(0) or first_route(route_map)
        if not route_id:
            continue
        statements.append(
            insert(
                "promo_codes",
                {
                    "id": promo_id,
                    "route_id": route_id,
                    "code": text(row, "code").upper(),
                    "name": text(row, "name"),
                    "apk_url": none_if_empty(text(row, "apk_url")),
                    "enabled": bool_int(row, "enabled", 1),
                    "created_at": timestamp(row, "created_at"),
                },
                conflict="ON CONFLICT (route_id, code) DO NOTHING",
            )
        )

    for row in rows(conn, "visits"):
        visit_id = new_uuid()
        legacy_id = int(row["id"])
        visit_map[legacy_id] = visit_id
        old_route_id = int_value(row, "route_id")
        route_id = route_map.get(old_route_id) or route_map.get(0) or first_route(route_map)
        promo_id = promo_by_code(conn, promo_map, row, old_route_id)
        statements.append(
            insert(
                "visits",
                {
                    "id": visit_id,
                    "route_id": route_id,
                    "promo_id": promo_id,
                    "promo_code": text(row, "promo_code").upper(),
                    "page_variant": page_variant(text(row, "page_variant", "unknown")),
                    "cloak_reason": text(row, "cloak_reason"),
                    "entry_domain": clean_domain(text(row, "entry_domain")),
                    "exit_domain": clean_domain(text(row, "exit_domain")),
                    "ip": none_if_empty(text(row, "ip")),
                    "ip_source": text(row, "ip_source"),
                    "cf_ray": text(row, "cf_ray"),
                    "country": text(row, "country"),
                    "province": text(row, "province"),
                    "city": text(row, "city"),
                    "isp": text(row, "isp"),
                    "os": text(row, "os"),
                    "os_version": text(row, "os_version"),
                    "device": text(row, "device"),
                    "browser": text(row, "browser"),
                    "language": text(row, "language"),
                    "referer": text(row, "referer"),
                    "user_agent": text(row, "user_agent"),
                    "created_at": timestamp(row, "created_at"),
                },
            )
        )
        if any(text(row, key) for key in ["screen", "timezone", "network", "fingerprint"]):
            statements.append(
                insert(
                    "visit_client_updates",
                    {
                        "visit_id": visit_id,
                        "screen": text(row, "screen"),
                        "timezone": text(row, "timezone"),
                        "network": text(row, "network"),
                        "fingerprint": text(row, "fingerprint"),
                        "updated_at": timestamp(row, "created_at"),
                    },
                )
            )
        if int_value(row, "downloaded") == 1:
            statements.append(
                insert(
                    "download_events",
                    {
                        "route_id": route_id,
                        "visit_id": visit_id,
                        "promo_id": promo_id,
                        "event_id": f"legacy_{legacy_id}",
                        "apk_url": "",
                        "created_at": timestamp(row, "created_at"),
                    },
                )
            )

    for row in rows(conn, "ip_blacklist"):
        statements.append(
            insert(
                "ip_blacklist",
                {
                    "cidr": text(row, "cidr"),
                    "note": text(row, "note"),
                    "created_at": timestamp(row, "created_at"),
                },
                conflict="ON CONFLICT (cidr) DO UPDATE SET note = EXCLUDED.note",
            )
        )

    statements.append("COMMIT;")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(statements) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


def rows(conn: sqlite3.Connection, table: str):
    if not has_table(conn, table):
        return []
    return conn.execute(f"SELECT * FROM {table}").fetchall()


def has_table(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table,)
    ).fetchone() is not None


def first_current(conn: sqlite3.Connection, table: str):
    return conn.execute(f"SELECT * FROM {table} ORDER BY is_current DESC, id DESC LIMIT 1").fetchone()


def first_route(route_map: dict[int, str]) -> str | None:
    return next(iter(route_map.values()), None)


def promo_by_code(conn, promo_map, visit_row, old_route_id):
    code = text(visit_row, "promo_code").upper()
    if not code or not has_table(conn, "promo_codes"):
        return None
    row = conn.execute(
        "SELECT id FROM promo_codes WHERE UPPER(code)=? AND (route_id IS NULL OR route_id=?) ORDER BY route_id DESC LIMIT 1",
        (code, old_route_id),
    ).fetchone()
    if not row:
        return None
    return promo_map.get(int(row["id"]))

def insert(table: str, values: dict, conflict: str = "") -> str:
    cols = ", ".join(values.keys())
    vals = ", ".join(sql(v) for v in values.values())
    suffix = f" {conflict}" if conflict else ""
    return f"INSERT INTO {table} ({cols}) VALUES ({vals}){suffix};"


def allowlist(domain: str) -> str:
    return insert(
        "domain_allowlist",
        {"domain": domain, "source": "legacy", "enabled": True},
        "ON CONFLICT (domain) DO UPDATE SET enabled = TRUE, source = 'legacy'",
    )


def sql(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int) or isinstance(value, float):
        return str(value)
    if isinstance(value, str) and is_uuid(value):
        return quote(value)
    return quote(str(value))


def quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def text(row, key: str, default: str = "") -> str:
    if key not in row.keys():
        return default
    value = row[key]
    if value is None:
        return default
    return str(value)


def int_value(row, key: str, default: int = 0) -> int:
    try:
        value = row[key] if key in row.keys() else default
        return int(value or default)
    except (TypeError, ValueError):
        return default


def number_value(row, key: str, default: float = 0) -> float:
    try:
        value = row[key] if key in row.keys() else default
        return float(value or default)
    except (TypeError, ValueError):
        return default


def bool_int(row, key: str, default: int = 0) -> bool:
    return int_value(row, key, default) == 1


def timestamp(row, key: str) -> str:
    value = text(row, key)
    if not value:
        return now()
    value = value.replace("T", " ").replace("Z", "")
    if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", value):
        return value
    return now()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S%z")


def clean_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    return value.split("/")[0].split(":")[0].strip()


def none_if_empty(value: str):
    value = value.strip()
    return value if value else None


def page_variant(value: str) -> str:
    return value if value in {"real", "fake", "probe", "unknown"} else "unknown"


def new_uuid() -> str:
    return str(uuid.uuid4())


if __name__ == "__main__":
    sys.exit(main())
