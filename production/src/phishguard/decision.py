"""Score -> action.

The PoC applied one threshold (0.85) in a metrics consumer, which meant the
"decision" only existed as a Grafana counter. Here the decision is its own
step, with separate thresholds per action because the costs differ:

  TAG         a false positive costs a banner on a legitimate email. Cheap,
              so the threshold can be lower.
  QUARANTINE  a false positive hides a legitimate (maybe urgent) email from
              someone. Expensive, so the threshold is higher.

Allowlisting is the classic way to get breached: attackers spoof allowlisted
senders. So an allowlisted domain only bypasses scoring when DMARC passed AND
that result came from our own MTA.
"""

from __future__ import annotations

import time

from .schema import Action, EmailEvent, Reason, Verdict
from .scoring.rules import registrable_domain


class Policy:
    def __init__(self, tag_threshold: float, quarantine_threshold: float,
                 allowlisted_sender_domains: tuple[str, ...] = ()):
        if not 0 <= tag_threshold <= quarantine_threshold <= 1:
            raise ValueError("need 0 <= tag_threshold <= quarantine_threshold <= 1")
        self.tag_threshold = tag_threshold
        self.quarantine_threshold = quarantine_threshold
        self.allowlist = {registrable_domain(d) for d in allowlisted_sender_domains}

    def decide(self, event: EmailEvent, score: float, reasons: list[Reason], *, model_name: str,
               model_version: str, model_score: float | None, now: float | None = None) -> Verdict:
        action = self._action(score)
        if (action is not Action.ALLOW and registrable_domain(event.from_domain) in self.allowlist
                and event.auth.trusted and event.auth.dmarc == "pass"):
            reasons = [Reason("allowlisted_sender", 0.0,
                              f"{event.from_domain} allowlisted and DMARC passed (would have been {action.value})"),
                       *reasons]
            action = Action.ALLOW
        return Verdict(message_id=event.message_id, event_id=event.event_id, score=score, action=action, reasons=reasons,
                       model_name=model_name, model_version=model_version, model_score=model_score,
                       scored_at=now if now is not None else time.time())

    def _action(self, score: float) -> Action:
        if score >= self.quarantine_threshold:
            return Action.QUARANTINE
        if score >= self.tag_threshold:
            return Action.TAG
        return Action.ALLOW
