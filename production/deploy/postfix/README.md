# Wiring ingest into Postfix as a copy, not a delivery transport

In the PoC, `email_to_kafka.py` was the delivery transport, so mail went to
Kafka and never to a mailbox. The setup below sends a **copy** of each
inbound message to the pipeline and leaves normal delivery alone.

`/etc/postfix/main.cf`
```
recipient_bcc_maps = regexp:/etc/postfix/phishguard_bcc
transport_maps = hash:/etc/postfix/transport
phishguard_destination_recipient_limit = 1
```

`/etc/postfix/phishguard_bcc` (copy everything addressed to our domain)
```
/@example-corp\.com$/   phishguard@phishguard.internal
```

`/etc/postfix/transport`
```
phishguard.internal   phishguard:
```

`/etc/postfix/master.cf`
```
phishguard unix  -  n  n  -  10  pipe
  flags=Rq user=phishguard argv=/opt/phishguard/bin/phishguard ingest
```

Then `postmap /etc/postfix/transport && postfix reload`.

Exit codes from `phishguard ingest`: `0` accepted, `75` temporary failure
(Postfix keeps the copy queued and retries), `65` permanent failure. Any
other status would be a hard bounce, so `ingest` turns every crash into 75.
If even the Python interpreter can't start (broken venv), the status is
outside our control, so point `argv` at a wrapper script that ends with
`|| exit 75`.

Two things to know about BCC copies:

* They're sent without delivery notifications, so a bounced copy notifies
  nobody. It shows up only in the mail log, which is why permanent failures
  (65) are logged at ERROR and should be alerted on.
* The copy's envelope recipient is the pipeline address, so the original
  envelope recipients (including Bcc'd victims) are lost. See DESIGN §12.

To **block** mail before delivery instead, the integration point is a milter
(`smtpd_milters`) or an after-queue content filter that re-injects mail with
a verdict header. That puts scoring on the delivery path, so it needs a
latency budget and an explicit fail-open/fail-closed decision. See
docs/DESIGN.md §2.

In a Microsoft 365 / Exchange environment the equivalent is journaling or the
Graph API for intake, and Graph API message moves for remediation.
