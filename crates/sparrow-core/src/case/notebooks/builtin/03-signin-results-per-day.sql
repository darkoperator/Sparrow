-- Failed and successful sign-ins per account per day
-- A burst of failures followed by a success is a guessed or sprayed password; failures alone
-- are an attempt. Days are UTC.
SELECT CAST(make_timestamp(epoch_us(event_time)) AS DATE) AS day,
       actor_upn AS account,
       count(*) FILTER (WHERE operation = 'SignInSucceeded') AS succeeded,
       count(*) FILTER (WHERE operation = 'SignInFailed') AS failed,
       count(DISTINCT ip) AS ips
FROM events
WHERE source LIKE 'signin%' AND event_time IS NOT NULL
GROUP BY ALL
ORDER BY day, account;
