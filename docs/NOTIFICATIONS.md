# Setting up Teams and email notifications

Notifications are sent when **new releases are published** and when **a run fails**. Each channel
is optional and turns on only when its secrets exist.

Where to add the secrets: GitHub → `jaydxt/Windows_Release_History` → **Settings → Secrets and
variables → Actions → New repository secret**. Secret values are encrypted, never shown in logs, and
only the two notification steps of the workflow can read them.

---

## 1. Microsoft Teams → `TEAMS_WEBHOOK_URL`

1. In Teams, open the **team and channel** that should receive the alerts.
2. Next to the channel name click **⋯ (More options) → Workflows**.
3. Search for the template **"Send webhook alerts to a channel"** and select it.
4. Name it, e.g. `Windows patch catalog`, and click **Next**.
5. Confirm the **Team** and **Channel**, and click **Add workflow**.
6. Copy the URL shown on the final screen (it starts with `https://` and contains
   `.../workflows/.../triggers/manual/paths/invoke?...sig=...`) → click **Done**.
7. In GitHub create the secret **`TEAMS_WEBHOOK_URL`** and paste the URL as the value.

Lost the URL? Teams → **Workflows** app → open the workflow → **Edit** → select the first step,
*"When a Teams webhook request is received"*, and copy **HTTP POST URL**.

Security notes
- The URL works like a password: anyone who has it can post to that channel. Keep it only in the
  GitHub secret. If it leaks, delete the workflow and create a new one.
- The workflow posts only to the channel you picked. It cannot read Teams messages.

---

## 2. Email (SMTP) → `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_TO`, `MAIL_FROM`

Use a **dedicated sending account**, not your personal mailbox, so the password can only send these
alerts and can be revoked on its own.

### Option A – Gmail / Google Workspace account (simplest)

1. Sign in to the sending Google account → <https://myaccount.google.com/security>.
2. Turn on **2-Step Verification** (required for app passwords).
3. Open <https://myaccount.google.com/apppasswords>, enter the app name `Windows patch catalog`, and
   click **Create**. Copy the 16-character password (spaces don't matter).
4. Create these GitHub secrets:

| Secret | Value |
|---|---|
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |
| `SMTP_USERNAME` | the sending Gmail address |
| `SMTP_PASSWORD` | the 16-character app password, **not** the account password |
| `MAIL_TO` | recipients, comma-separated, e.g. `jaydxt@gmail.com,secops@contoso.com` |
| `MAIL_FROM` | optional; defaults to `SMTP_USERNAME` |

To revoke: delete the app password on the same page. The account password is unaffected.

### Option B – Corporate email via a mail-sending service

Microsoft 365 is retiring basic SMTP authentication for Exchange Online, so `smtp.office365.com` with
a username and password is not a long-term option. If mail must come from a company domain, use a mail
relay your messaging team approves, e.g. SendGrid, Mailjet, Brevo or Azure Communication Services
Email. Create an **API key limited to "Mail Send"** and enter it as `SMTP_PASSWORD`. Each service lists
its SMTP host and username on the API-key page; port 587 works with all of them.

### Option C – No SMTP at all

- GitHub already emails the repository owner when a workflow run fails (**Settings → Notifications
  → Actions** on your GitHub profile).
- Teams channels have an email address too: channel **⋯ → Get email address**. Mail sent to it
  appears in the channel, and the Teams alert itself can be forwarded from there.

---

## 3. Test it

A normal run only notifies when new releases appear, so test each channel from a PC that has the repo
and Python:

```powershell
$env:TEAMS_WEBHOOK_URL = '<url>'   # this PowerShell window only
python -I scripts/notify.py --status failure
Remove-Item Env:TEAMS_WEBHOOK_URL
```
