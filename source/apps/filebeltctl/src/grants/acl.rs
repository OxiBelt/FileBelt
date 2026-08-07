// SPDX-License-Identifier: Apache-2.0

//! Catalog-wide rejection of grants to principals outside the reviewed roles.

use filebelt_database::Database;
use sqlx::Row as _;

use super::{ROLES, SCHEMAS};

pub(super) async fn verify_unlisted_acl_grantees(
    database: &Database,
    failures: &mut Vec<String>,
) -> Result<(), String> {
    let rows = sqlx::query(
        r#"
WITH acl_entries AS (
  SELECT 'schema'::text AS kind,n.nspname AS object_name,n.nspowner AS owner_id,
         a.grantee
    FROM pg_namespace n
    CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
    WHERE n.nspname=ANY($1)
  UNION ALL
  SELECT 'relation',format('%I.%I',n.nspname,c.relname),c.relowner,a.grantee
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault(
      CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) a
    WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','f','S')
  UNION ALL
  SELECT 'column',format('%I.%I.%I',n.nspname,c.relname,att.attname),c.relowner,a.grantee
    FROM pg_attribute att JOIN pg_class c ON c.oid=att.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(att.attacl) a
    WHERE n.nspname=ANY($1) AND att.attnum>0 AND NOT att.attisdropped
  UNION ALL
  SELECT 'function',p.oid::regprocedure::text,p.proowner,a.grantee
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
    WHERE n.nspname=ANY($1)
  UNION ALL
  SELECT 'type',format('%I.%I',n.nspname,t.typname),t.typowner,a.grantee
    FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(t.typacl,acldefault('T',t.typowner))) a
    WHERE n.nspname=ANY($1) AND t.typrelid=0 AND t.typelem=0
      AND t.typtype IN ('b','c','d','e','m','r')
), unexpected AS (
  SELECT kind,object_name,grantee FROM acl_entries a
  LEFT JOIN pg_roles r ON r.oid=a.grantee
  WHERE a.grantee<>a.owner_id
    AND (a.kind='type' OR a.grantee=0 OR NOT r.rolname=ANY($2))
)
SELECT kind,object_name,COALESCE(r.rolname,'PUBLIC') AS grantee
  FROM unexpected u LEFT JOIN pg_roles r ON r.oid=u.grantee
  ORDER BY kind,object_name,grantee
"#,
    )
    .bind(SCHEMAS)
    .bind(ROLES)
    .fetch_all(database.pool())
    .await
    .map_err(|error| error.to_string())?;
    for row in rows {
        failures.push(format!(
            "unreviewed ACL grantee {} on {} {}",
            row.get::<String, _>("grantee"),
            row.get::<String, _>("kind"),
            row.get::<String, _>("object_name")
        ));
    }

    let defaults = sqlx::query(
        r#"
SELECT d.defaclobjtype::text AS object_type,
       COALESCE(n.nspname,'all schemas') AS schema_name,
       owner.rolname AS owner
  FROM pg_default_acl d
  LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
  JOIN pg_roles owner ON owner.oid=d.defaclrole
 WHERE (d.defaclnamespace=0 OR n.nspname=ANY($1))
 ORDER BY object_type,schema_name,owner
"#,
    )
    .bind(SCHEMAS)
    .fetch_all(database.pool())
    .await
    .map_err(|error| error.to_string())?;
    for row in defaults {
        failures.push(format!(
            "prohibited default ACL owned by {} for object type {} in {}",
            row.get::<String, _>("owner"),
            row.get::<String, _>("object_type"),
            row.get::<String, _>("schema_name")
        ));
    }
    let memberships = sqlx::query(
        "SELECT member.rolname AS member,parent.rolname AS parent FROM pg_auth_members membership JOIN pg_roles member ON member.oid=membership.member JOIN pg_roles parent ON parent.oid=membership.roleid WHERE member.rolname=ANY($1) AND NOT parent.rolname=ANY($1) ORDER BY member.rolname,parent.rolname",
    )
    .bind(ROLES)
    .fetch_all(database.pool())
    .await
    .map_err(|error| error.to_string())?;
    for row in memberships {
        failures.push(format!(
            "reviewed role {} inherits unreviewed role {}",
            row.get::<String, _>("member"),
            row.get::<String, _>("parent")
        ));
    }
    Ok(())
}
