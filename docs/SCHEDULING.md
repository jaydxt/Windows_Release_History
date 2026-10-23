# Where the scheduled job runs

## Default: GitHub Actions (recommended, no device needed)

The schedule lives in `.github/workflows/update-catalog.yml` and runs on **GitHub's servers**, not on
any of your PCs. Nothing has to be installed or left switched on anywhere. It runs:

- daily at 06:30 UTC from the 8th to the 16th of each month (the Patch Tuesday window), and
- every Monday at 06:30 UTC (out-of-band releases and Microsoft corrections).

Manage it at GitHub → **Actions → Update Windows security release catalog**: **Run workflow** runs
it now, **⋯ → Disable workflow** pauses it, and the run history shows every past run with its logs.

To change the times, edit the two `cron:` lines (UTC; format `minute hour day month weekday`).

## Alternative: Windows Task Scheduler on another device

Use this only if the job must run inside your network. **Disable the GitHub workflow first**
(Actions → workflow → **⋯ → Disable workflow**) so the two don't run at the same time.

### On the device (standard user account; no admin rights needed)

1. Install **Git for Windows** and **Python 3.10 or newer** (tick *Add python.exe to PATH*).
   No Python packages are needed.
2. Create a **fine-grained personal access token** limited to this repository:
   GitHub → profile picture → **Settings → Developer settings → Personal access tokens →
   Fine-grained tokens → Generate new token**
   - Expiration: 90 days. Put a renewal reminder in your calendar.
   - Repository access: **Only select repositories** → `jaydxt/Windows_Release_History`
   - Repository permissions: **Contents → Read and write**. Leave every other permission at *No access*.
3. Clone the repo and sign in once (Git Credential Manager stores the token securely):
   ```powershell
   git clone https://github.com/jaydxt/Windows_Release_History.git C:\WindowsPatchCatalog
   cd C:\WindowsPatchCatalog
   git config user.name "Windows Patch Catalog"
   git config user.email "jaydxt@users.noreply.github.com"
   git pull   # when prompted, choose "Token" and paste the fine-grained token
   ```
4. (Optional) store notification settings, encrypted for this user on this device only:
   ```powershell
   .\scripts\windows\Set-NotificationSecrets.ps1
   ```
5. Test a run, then create the scheduled task:
   ```powershell
   .\scripts\windows\Update-Catalog.ps1
   .\scripts\windows\Register-CatalogTask.ps1 -At 07:30
   ```
   The task runs daily as your standard user with limited privileges, logged on or not.
   Logs: `%LOCALAPPDATA%\WindowsPatchCatalog\logs` (the last 60 runs are kept).

To remove it: `Unregister-ScheduledTask -TaskName 'Windows Patch Catalog'`, delete the token on
GitHub, and re-enable the GitHub workflow.
