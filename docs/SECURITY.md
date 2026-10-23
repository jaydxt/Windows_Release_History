# Security design (least privilege)

| Area | Control |
|---|---|
| **Workflow token** | `permissions: {}` by default; the one job gets only `contents: write` for this repo. No issues, packages, or pull-request rights. |
| **Token exposure** | `actions/checkout` uses `persist-credentials: false`, so the token is not in `.git/config` while the scripts run. It is passed only to the push step. |
| **Third-party code** | One action (`actions/checkout`), **pinned to a full commit SHA** so a changed tag cannot alter it. Dependabot proposes updates as pull requests for review. No Python packages are installed: the scripts use the Python standard library only. |
| **Secrets** | Teams and SMTP secrets are GitHub encrypted secrets, exposed only to the two notification steps and never to the build step. Error messages print only the error type, never URLs or server replies. |
| **Script injection** | Workflow inputs and step outputs reach shell commands only through environment variables, never through `${{ }}` inside scripts. |
| **Branch** | The job publishes only when running on the default branch. |
| **Network** | The build script fetches only `https://api.msrc.microsoft.com/cvrf/v3.0/...` (other hosts are refused), with TLS certificate checks and a 200 MB response cap. SMTP uses STARTTLS with certificate checks before any password is sent. The Teams URL must be HTTPS. |
| **Input handling** | MSRC document IDs are checked against a strict pattern before being used as file names. Data is parsed as JSON only; nothing from MSRC is executed. |
| **Publishing safety** | The CSV is validated before it is written: minimum rows, no >5% drop, month never goes backwards, no duplicates, and serviced OS versions present. A failed run leaves the last good file in place. |
| **Defender access (KQL / Power BI)** | Read-only. Power BI uses *your* delegated sign-in to the Advanced Hunting API, so it sees only what your Defender role allows. No app registration, client secret or tenant-wide permission is created. Use an account with the **Security Reader** role or a custom Defender role with only *Security operations → Security data → Read* (Advanced hunting). |
| **Public data only** | The repository holds only Microsoft's public release data. No device names or tenant data are ever committed. Device data stays in Defender and in your Power BI file. |
| **Task Scheduler option** | Standard user, *Limited* run level, a fine-grained token for one repo with Contents read/write only and an expiry date, and notification secrets DPAPI-encrypted per user and machine. See `SCHEDULING.md`. |

Recommended repository settings (GitHub → Settings):
- **Actions → General → Workflow permissions:** *Read and write* (needed to commit the CSV). Leave
  *Allow GitHub Actions to create and approve pull requests* **unticked**.
- **Actions → General → Actions permissions:** *Allow jaydxt, and select non-jaydxt, actions* →
  allow only `actions/checkout@*`.
- **Code security:** enable **Secret scanning** and **Push protection** (free for public repos).
