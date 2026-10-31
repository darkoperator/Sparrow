-- First use of each user agent and device per account
-- When each account first used a client (user agent) or a device, newest first. A client or
-- device that appears in the middle of the incident and was never seen before is a lead.
SELECT account, kind, value, first_seen, last_seen, events
FROM (
    SELECT actor_upn AS account, 'user agent' AS kind, user_agent AS value,
           min(event_time) AS first_seen, max(event_time) AS last_seen, count(*) AS events
    FROM events
    WHERE actor_upn IS NOT NULL AND user_agent IS NOT NULL
    GROUP BY actor_upn, user_agent
    UNION ALL
    SELECT actor_upn, 'device', coalesce(device_name || ' (' || device_id || ')', device_id),
           min(event_time), max(event_time), count(*)
    FROM events
    WHERE actor_upn IS NOT NULL AND device_id IS NOT NULL
    GROUP BY actor_upn, device_id, device_name
)
ORDER BY first_seen DESC NULLS LAST;
