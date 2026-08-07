// SPDX-License-Identifier: Apache-2.0

//! Bounded, snapshot-consistent audit export.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

const SCHEMA: &str = "filebelt.audit.export.v1";
const CURSOR_PREFIX: &str = "v1.";
const MAX_CURSOR_BYTES: usize = 2_048;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Point {
    occurred_at: String,
    id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Cursor {
    position: Point,
    watermark: Point,
}

pub async fn export(
    database: &Database,
    tenant_slug: &str,
    after: Option<&str>,
    limit: u32,
) -> Result<String, String> {
    if !(1..=10_000).contains(&limit) {
        return Err("audit export limit must be between 1 and 10000".into());
    }
    let after_cursor = after.map(decode_cursor).transpose()?;
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let tenant_id = sqlx::query("SELECT id FROM tenants WHERE slug=$1")
        .bind(tenant_slug)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?
        .map(|row| row.get::<Uuid, _>("id"))
        .ok_or_else(|| "configured tenant was not found".to_owned())?;
    let watermark = if let Some(cursor) = &after_cursor {
        Some(cursor.watermark.clone())
    } else {
        sqlx::query(
            "SELECT occurred_at::text AS occurred_at,id FROM audit_events WHERE tenant_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?
        .map(|row| Point {
            occurred_at: row.get("occurred_at"),
            id: row.get("id"),
        })
    };
    let rows = sqlx::query(
        "SELECT id,actor_principal_id,target_principal_id,resource_id,action,outcome,reason_code,privacy_visible,request_id,details,occurred_at::text AS occurred_at FROM audit_events WHERE tenant_id=$1 AND ($2::timestamptz IS NULL OR (occurred_at,id)>($2::timestamptz,$3::uuid)) AND ($4::timestamptz IS NULL OR (occurred_at,id)<=($4::timestamptz,$5::uuid)) ORDER BY occurred_at,id LIMIT $6",
    )
    .bind(tenant_id)
    .bind(
        after_cursor
            .as_ref()
            .map(|cursor| cursor.position.occurred_at.as_str()),
    )
    .bind(after_cursor.as_ref().map(|cursor| cursor.position.id))
    .bind(watermark.as_ref().map(|cursor| cursor.occurred_at.as_str()))
    .bind(watermark.as_ref().map(|cursor| cursor.id))
    .bind(i64::from(limit))
    .fetch_all(&mut *transaction)
    .await
    .map_err(|error| error.to_string())?;

    let mut records = Vec::with_capacity(rows.len() + 2);
    records.push(json!({
        "schema": SCHEMA,
        "record": "header",
        "tenant_id": tenant_id,
        "tenant_slug": tenant_slug,
        "after": after,
        "snapshot_watermark": watermark.as_ref().map(|point| encode_cursor(&Cursor {
            position: point.clone(),
            watermark: point.clone(),
        })),
        "limit": limit,
    }));
    let mut last_cursor = None;
    for row in rows {
        let point = Point {
            occurred_at: row.get("occurred_at"),
            id: row.get("id"),
        };
        records.push(json!({
            "schema": SCHEMA,
            "record": "event",
            "tenant_id": tenant_id,
            "id": point.id,
            "actor_principal_id": row.get::<Option<Uuid>, _>("actor_principal_id"),
            "target_principal_id": row.get::<Option<Uuid>, _>("target_principal_id"),
            "resource_id": row.get::<Option<Uuid>, _>("resource_id"),
            "action": row.get::<String, _>("action"),
            "outcome": row.get::<String, _>("outcome"),
            "reason_code": row.get::<String, _>("reason_code"),
            "privacy_visible": row.get::<bool, _>("privacy_visible"),
            "request_id": row.get::<Option<Uuid>, _>("request_id"),
            "details": row.get::<Value, _>("details"),
            "occurred_at": &point.occurred_at,
        }));
        last_cursor = Some(point);
    }
    let complete = match (&watermark, &last_cursor) {
        (None, _) | (_, None) => true,
        (Some(watermark), Some(last)) => watermark == last,
    };
    records.push(json!({
        "schema": SCHEMA,
        "record": "checkpoint",
        "next_cursor": last_cursor.as_ref().and_then(|position| watermark.as_ref().map(|watermark| encode_cursor(&Cursor {
            position: position.clone(),
            watermark: watermark.clone(),
        }))).or_else(|| after.map(str::to_owned)),
        "snapshot_watermark": watermark.as_ref().map(|point| encode_cursor(&Cursor {
            position: point.clone(),
            watermark: point.clone(),
        })),
        "complete": complete,
    }));
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    records
        .into_iter()
        .map(|record| serde_json::to_string(&record).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map(|records| records.join("\n"))
}

fn encode_cursor(cursor: &Cursor) -> String {
    let payload = json!({
        "position_occurred_at": cursor.position.occurred_at,
        "position_id": cursor.position.id,
        "watermark_occurred_at": cursor.watermark.occurred_at,
        "watermark_id": cursor.watermark.id,
    });
    format!(
        "{CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(payload.to_string())
    )
}

fn decode_cursor(encoded: &str) -> Result<Cursor, String> {
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err("audit cursor is too large".into());
    }
    let payload = encoded
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| "audit cursor version is unsupported".to_owned())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "audit cursor encoding is invalid".to_owned())?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "audit cursor payload is invalid".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "audit cursor payload is invalid".to_owned())?;
    if object.len() != 4 {
        return Err("audit cursor fields are invalid".into());
    }
    let timestamp = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .map(str::to_owned)
            .ok_or_else(|| "audit cursor timestamp is invalid".to_owned())
    };
    let uuid = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| "audit cursor id is invalid".to_owned())?
            .parse()
            .map_err(|_| "audit cursor id is invalid".to_owned())
    };
    let cursor = Cursor {
        position: Point {
            occurred_at: timestamp("position_occurred_at")?,
            id: uuid("position_id")?,
        },
        watermark: Point {
            occurred_at: timestamp("watermark_occurred_at")?,
            id: uuid("watermark_id")?,
        },
    };
    if (cursor.position.occurred_at.as_str(), cursor.position.id)
        > (cursor.watermark.occurred_at.as_str(), cursor.watermark.id)
    {
        return Err("audit cursor position exceeds its snapshot watermark".into());
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_is_versioned_and_opaque() {
        let cursor = Cursor {
            position: Point {
                occurred_at: "2026-08-07 12:13:14+00".into(),
                id: Uuid::parse_str("0198d1e4-bf39-7f65-9029-11eedf35de88").expect("UUID"),
            },
            watermark: Point {
                occurred_at: "2026-08-07 12:14:00+00".into(),
                id: Uuid::parse_str("0198d1e4-c573-71a2-b8bb-f0c4d57a17bc").expect("UUID"),
            },
        };
        let encoded = encode_cursor(&cursor);
        assert!(encoded.starts_with(CURSOR_PREFIX));
        assert_eq!(decode_cursor(&encoded).expect("decode cursor"), cursor);
    }

    #[test]
    fn cursor_rejects_unknown_fields_and_versions() {
        assert!(decode_cursor("v2.e30").is_err());
        let payload = URL_SAFE_NO_PAD.encode(
            json!({
                "position_occurred_at": "2026-08-07 12:13:14+00",
                "position_id": Uuid::nil(),
                "watermark_occurred_at": "2026-08-07 12:14:00+00",
                "watermark_id": Uuid::nil(),
                "tenant": Uuid::nil(),
            })
            .to_string(),
        );
        assert!(decode_cursor(&format!("v1.{payload}")).is_err());
    }
}
