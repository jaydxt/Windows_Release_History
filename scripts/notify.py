"""Send the catalog run result to Microsoft Teams and/or email.

Each channel is used only when its settings are present (GitHub Actions secrets -> env vars):
  Teams : TEAMS_WEBHOOK_URL   (Teams "Workflows" webhook: "Send webhook alerts to a channel")
  Email : SMTP_HOST, SMTP_PORT (default 587, STARTTLS), SMTP_USERNAME, SMTP_PASSWORD,
          MAIL_FROM (defaults to SMTP_USERNAME), MAIL_TO (comma-separated)

Usage:
  python scripts/notify.py --status success --summary-file summary.md
  python scripts/notify.py --status failure
"""
from __future__ import annotations

import argparse
import json
import os
import smtplib
import ssl
import sys
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path


def run_url() -> str:
    if not os.environ.get("GITHUB_RUN_ID"):
        return ""
    return (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}")


def send_teams(webhook: str, title: str, body: str, success: bool, link: str) -> None:
    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": [
            {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True,
             "color": "Good" if success else "Attention"},
            *[{"type": "TextBlock", "text": line, "wrap": True, "spacing": "None"}
              for line in body.splitlines() if line.strip()],
        ],
        "actions": [{"type": "Action.OpenUrl", "title": "Open workflow run", "url": link}] if link else [],
    }
    if urllib.parse.urlsplit(webhook).scheme != "https":
        raise ValueError("TEAMS_WEBHOOK_URL must be an https:// URL")
    payload = {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
    request = urllib.request.Request(webhook, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
        if response.status >= 300:
            raise RuntimeError(f"Teams webhook returned HTTP {response.status}")


def send_email(title: str, body: str, link: str) -> None:
    message = EmailMessage()
    message["Subject"] = title
    message["From"] = os.environ.get("MAIL_FROM") or os.environ["SMTP_USERNAME"]
    message["To"] = ", ".join(a.strip() for a in os.environ["MAIL_TO"].split(",") if a.strip())
    message.set_content(body.replace("**", "") + (f"\nWorkflow run: {link}\n" if link else ""))
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT") or 587), timeout=30) as smtp:
        smtp.starttls(context=ssl.create_default_context())  # verified TLS before credentials are sent
        smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        smtp.send_message(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--status", choices=("success", "failure"), required=True)
    parser.add_argument("--summary-file", type=Path)
    args = parser.parse_args()

    success = args.status == "success"
    link = run_url()
    if success:
        title = "Windows security release catalog updated"
        body = args.summary_file.read_text(encoding="utf-8") if args.summary_file and args.summary_file.exists() else ""
    else:
        title = "Windows security release catalog update FAILED"
        body = ("The scheduled update did not complete. The published CSV was not changed, so the "
                "dashboard keeps showing the previous data. Open the workflow run for the error.")

    channels = {}
    if os.environ.get("TEAMS_WEBHOOK_URL"):
        channels["Teams"] = lambda: send_teams(os.environ["TEAMS_WEBHOOK_URL"], title, body, success, link)
    if all(os.environ.get(k) for k in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "MAIL_TO")):
        channels["Email"] = lambda: send_email(title, body, link)
    if not channels:
        print("No notification channel configured; skipping.")
        return 0

    failed = []
    for name, send in channels.items():
        try:
            send()
            print(f"{name} notification sent.")
        except Exception as error:  # report every channel before failing
            # Error type only: messages from SMTP/HTTP libraries can echo server details or URLs.
            print(f"::warning::{name} notification failed: {type(error).__name__}")
            failed.append(name)
    return 1 if len(failed) == len(channels) else 0


if __name__ == "__main__":
    sys.exit(main())
