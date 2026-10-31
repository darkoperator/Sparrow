-- Successful sign-ins from hosting providers
-- Users rarely sign in from a data centre; an adversary-in-the-middle proxy or a rented VPS
-- usually does. Each row is one account and IP, with how often and when.
SELECT actor_upn AS account, ip, ip_country AS country, asn, asn_org,
       count(*) AS sign_ins,
       min(event_time) AS first_seen,
       max(event_time) AS last_seen,
       any_value(user_agent) AS a_user_agent
FROM events
WHERE source LIKE 'signin%' AND operation = 'SignInSucceeded' AND ip_kind = 'hosting'
GROUP BY actor_upn, ip, ip_country, asn, asn_org
ORDER BY first_seen;
