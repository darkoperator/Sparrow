-- Everything one IP touched, by account and operation
-- Every account, mailbox and operation seen from one IP, earliest first: the attacker's path
-- through the tenant when the IP is theirs.
-- Fill in [ip] with the IP, as the Events grid shows it.
SELECT actor_upn AS account, owner_upn AS mailbox, workload, operation,
       count(*) AS events,
       min(event_time) AS first_seen,
       max(event_time) AS last_seen
FROM events
WHERE ip = '[ip]'
GROUP BY ALL
ORDER BY first_seen;
