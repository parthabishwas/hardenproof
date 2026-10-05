# Security policy

HardenProof changes security-critical configuration on the hosts it runs against: SSH, PAM,
sudo, the firewall and the kernel audit system. A defect here can lock an administrator out
or leave a host less protected than its report claims. Reports of such defects are welcome.

## Reporting a vulnerability

Please report privately, not in a public issue:

1. Open the repository's **Security** tab and choose **Report a vulnerability** (GitHub
   private vulnerability reporting).
2. Include the HardenProof version or commit, the target's Ubuntu release, what you ran, and
   what happened. The run log under `reports/_logs/` and the relevant rows of `cis_audit.tsv`
   help most; remove host names and addresses you do not want to share.

You will get an acknowledgement, and a fix or a documented mitigation will be published with
credit to you unless you prefer otherwise. This is a small project maintained on a best-effort
basis, so no response time is promised.

## What counts

- A run that removes the access path (SSH, sudo) without the rollback guard restoring it.
- A control reported as PASS that is not in effect, or the reverse.
- The playbooks or scripts exposing credentials, or writing secrets to logs or reports.
- A way for an unprivileged user on a hardened host to undo or bypass a control HardenProof
  applied, where the benchmark intends that control to prevent exactly that.
- Command or template injection through inventory values or audit evidence, including into
  the HTML report.

## What does not

- Findings the audit already reports as open, manual or accepted.
- Weaknesses in software HardenProof downloads but does not ship (dev-sec, Lynis, Ubuntu
  packages). Report those upstream.
- Results on systems outside the supported list in the README.

## Supported versions

Only the latest release receives fixes.
