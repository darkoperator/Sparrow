-- Mail read per mailbox per day, by IP
-- MailItemsAccessed records per mailbox, day (UTC) and client IP: how much was read and from
-- where. A day with many records from an IP the mailbox owner never used is likely theft.
SELECT CAST(make_timestamp(epoch_us(event_time)) AS DATE) AS day,
       coalesce(owner_upn, actor_upn) AS mailbox,
       ip, ip_country AS country, asn_org,
       count(*) AS records
FROM events
WHERE (operation = 'MailItemsAccessed' OR source = 'mail_items_accessed') AND event_time IS NOT NULL
GROUP BY ALL
ORDER BY day, mailbox, records DESC;
