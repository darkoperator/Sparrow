-- Every operation by workload, rarest first
-- What happened in the tenant at all: each workload and operation with how often, how many
-- accounts did it, and when. Rare operations at the top are worth a look.
SELECT workload, operation,
       count(*) AS events,
       count(DISTINCT actor_upn) AS accounts,
       min(event_time) AS first_seen,
       max(event_time) AS last_seen
FROM events
GROUP BY workload, operation
ORDER BY events, workload, operation;
