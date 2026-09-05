"""APScheduler-based scheduled scanning."""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import config
import scanner
import models
import notifier

_scheduler = None


def run_scheduled_scan():
    """Scan all known root domains in parallel (sharded scan), notify changes."""
    roots = models.all_root_domains()
    for root, summary, discovered in scanner.scan_root_domains(roots):
        if isinstance(summary, dict) and "error" in summary:
            continue
        changes = [(d.get("domain", ""), d.get("change_type", "")) for d in discovered]
        notifier.notify_scan_complete(root, summary, changes)


def init_scheduler(app):
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None

    if not config.get_bool("scheduled_scan_enabled"):
        return

    time_str = config.get("scheduled_scan_time", "02:00")
    try:
        hour, minute = time_str.split(":")
        hour, minute = int(hour), int(minute)
    except (ValueError, AttributeError):
        hour, minute = 2, 0

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        run_scheduled_scan,
        CronTrigger(hour=hour, minute=minute),
        id="daily_scan",
        replace_existing=True,
    )
    _scheduler.start()
    app.logger.info(f"Scheduled scan initialized for {hour:02d}:{minute:02d} daily")


def reinit_scheduler(app):
    """Called when settings change."""
    init_scheduler(app)
