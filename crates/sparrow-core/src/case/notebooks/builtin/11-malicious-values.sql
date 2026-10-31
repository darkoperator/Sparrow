-- Every value flagged malicious, with the events it matches
-- Standing flags on IPs, ranges, accounts, ASNs, devices and sessions, agents' pending ones
-- included (see review_state), and how many events carry each value anywhere in the case.
-- A flag scoped to one entity counts its value case-wide here.
SELECT f.kind, f.value, f.scope_kind, f.scope_value, f.review_state, f.decided_by, f.decided_at,
       (SELECT count(*) FROM events e
        WHERE CASE CAST(f.kind AS VARCHAR)
                WHEN 'ip' THEN e.ip = f.value
                WHEN 'ip_prefix' THEN e.ip_prefix = f.value
                WHEN 'account' THEN e.actor_upn = f.value OR e.owner_upn = f.value
                WHEN 'asn' THEN CAST(e.asn AS VARCHAR) = f.value
                WHEN 'device' THEN e.device_id = f.value OR e.device_object_id = f.value
                WHEN 'session' THEN e.entra_session_id = f.value
                ELSE false
              END) AS events
FROM value_flags f
WHERE CAST(f.level AS VARCHAR) = 'malicious' AND f.removed_at IS NULL
ORDER BY events DESC, f.kind, f.value;
