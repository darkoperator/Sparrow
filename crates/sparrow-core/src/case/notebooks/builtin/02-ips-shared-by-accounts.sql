-- IPs used by more than one account
-- Public IPs (not private, not Microsoft) seen with several accounts, most accounts first.
-- One IP behind many accounts is shared attacker infrastructure, a password spray, or an
-- office or VPN egress; the ASN and the accounts column tell them apart.
SELECT ip, ip_country AS country, asn_org, ip_kind,
       count(DISTINCT actor_upn) AS accounts,
       count(*) AS events,
       min(event_time) AS first_seen,
       max(event_time) AS last_seen,
       string_agg(DISTINCT actor_upn, ', ' ORDER BY actor_upn) AS account_list
FROM events
WHERE ip IS NOT NULL AND actor_upn IS NOT NULL
  AND ip_kind IS DISTINCT FROM 'private' AND ip_kind IS DISTINCT FROM 'microsoft'
GROUP BY ip, ip_country, asn_org, ip_kind
HAVING count(DISTINCT actor_upn) > 1
ORDER BY accounts DESC, events DESC;
