"""Command line entry points.

    phishguard score FILE.eml [...]     score emails locally and explain the verdict (no Kafka)
    phishguard ingest                   Postfix pipe: read one message on stdin
    phishguard worker                   run the scoring worker
    phishguard evaluate ...             precision/recall against ground truth
    phishguard synth OUT_DIR            write a labelled synthetic corpus
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

from .config import Settings
from .decision import Policy
from .pipeline import Pipeline
from .scoring import RuleEngine, build_scorer


def _setup_logging() -> None:
    target = os.environ.get("PHISHGUARD_LOG_FILE")
    handler = logging.FileHandler(target) if target else logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('{"ts":"%(asctime)s","level":"%(levelname)s",'
                                           '"logger":"%(name)s","msg":"%(message)s"}'))
    logging.basicConfig(level=os.environ.get("PHISHGUARD_LOG_LEVEL", "INFO"), handlers=[handler])


def build_pipeline(settings: Settings) -> Pipeline:
    return Pipeline(
        RuleEngine(settings.protected_domains),
        build_scorer(settings.scorer, triton_url=settings.triton_url, triton_model=settings.triton_model),
        Policy(settings.tag_threshold, settings.quarantine_threshold, settings.allowlisted_sender_domains),
    )


def cmd_score(args, settings: Settings) -> int:
    from .parsing import parse_email
    pipeline = build_pipeline(settings)
    for path in args.files:
        event = parse_email(Path(path).read_bytes(), received_at=time.time(),
                            trusted_authserv_ids=settings.trusted_authserv_ids)
        verdict = pipeline.score([event])[0]
        out = asdict(verdict)
        out["action"] = verdict.action.value
        out["file"] = path
        if args.show_event:
            out["event"] = asdict(event)
        print(json.dumps(out, indent=2))
    return 0


def cmd_worker(_args, settings: Settings) -> int:
    from prometheus_client import start_http_server

    from .producer import ReliableProducer
    from .worker import Worker, build_consumer

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())  # finish the current batch, then exit
    start_http_server(settings.metrics_port)
    worker = Worker(build_consumer(settings), ReliableProducer(settings.bootstrap_servers),
                    build_pipeline(settings), settings)
    worker.run(stop.is_set)
    return 0


def cmd_evaluate(args, settings: Settings) -> int:
    from .evaluate import evaluate, from_eml_dir, from_files
    if args.eml_dir:
        labels, scores = from_eml_dir(args.eml_dir, build_pipeline(settings), model_only=args.model_only,
                                      trusted_authserv_ids=settings.trusted_authserv_ids)
    elif args.labels and args.verdicts:
        labels, scores = from_files(args.labels, args.verdicts)
    else:
        print("give --eml-dir, or both --labels and --verdicts", file=sys.stderr)
        return 2
    print(evaluate(labels, scores).format())
    return 0


def cmd_synth(args, _settings: Settings) -> int:
    from .synthetic import write_corpus
    n_phish, n_ham = write_corpus(args.out_dir, n=args.n, phishing_rate=args.phishing_rate, seed=args.seed)
    print(f"wrote {n_phish} phishing and {n_ham} legitimate emails to {args.out_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishguard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("score", help="score .eml files locally and explain the verdict")
    p.add_argument("files", nargs="+")
    p.add_argument("--show-event", action="store_true", help="also print the parsed event")
    p.set_defaults(fn=cmd_score)

    sub.add_parser("ingest", help="Postfix pipe entry point")
    sub.add_parser("worker", help="run the scoring worker").set_defaults(fn=cmd_worker)

    p = sub.add_parser("evaluate", help="precision/recall against ground truth")
    p.add_argument("--eml-dir")
    p.add_argument("--labels")
    p.add_argument("--verdicts")
    p.add_argument("--model-only", action="store_true", help="evaluate the text model alone, without rules")
    p.set_defaults(fn=cmd_evaluate)

    p = sub.add_parser("synth", help="write a labelled synthetic corpus")
    p.add_argument("out_dir")
    p.add_argument("--n", type=int, default=200)
    p.add_argument("--phishing-rate", type=float, default=0.3)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(fn=cmd_synth)

    args = parser.parse_args(argv)
    if args.cmd == "ingest":
        # Postfix treats any exit status other than 0/65/75 as a hard bounce, so even a failure
        # to set up logging (e.g. unwritable log file) must come out as "try again later".
        try:
            _setup_logging()
        except BaseException:
            return 75
        from .ingest import main as ingest_main
        return ingest_main()
    _setup_logging()
    return args.fn(args, Settings())


if __name__ == "__main__":
    sys.exit(main())
