-- Sign-ins per account by country and network
-- Where each account signed in from (country, ASN), how many sign-ins failed, and when each
-- place was first and last seen. A country or network that does not fit the user, such as a
-- hosting provider, is the first thing to look at.
-- Fill in [account] with a UPN, or with * for every account.
SELECT actor_upn AS account, ip_country AS country, asn, asn_org,
       count(*) AS sign_ins,
       count(*) FILTER (WHERE operation = 'SignInFailed') AS failed,
       min(event_time) AS first_seen,
       max(event_time) AS last_seen
FROM events
WHERE source LIKE 'signin%'
  AND ('[account]' = '*' OR actor_upn = lower('[account]'))
GROUP BY ALL
ORDER BY account, sign_ins DESC;
