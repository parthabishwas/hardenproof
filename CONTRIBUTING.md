# Contributing

HardenProof changes how people reach their servers, so a change is judged by evidence, not
by reading the diff.

## What a pull request needs

1. **The linters and tests pass.**

   ```bash
   .venv/bin/pip install -r requirements-dev.txt
   .venv/bin/shellcheck -S warning harden.sh audit/cis_audit.sh roles/hardening_extras/files/*.sh tests/*.sh
   .venv/bin/yamllint . && .venv/bin/ansible-lint playbooks roles
   PYTHON=.venv/bin/python tests/test_report.sh
   PYTHON=.venv/bin/python tests/test_wrapper.sh
   ```

2. **For any change to a playbook, the role or the audit script: a run on a real system.**
   CI cannot harden a host. Run the end-to-end test against a disposable machine of each
   Ubuntu release you can (fresh virtual machines are best):

   ```bash
   HARDEN_BECOME_PASS='...' tests/e2e.sh inventory/<env>/hosts.yml <host>
   ```

   It hardens the host, checks that a second run changes nothing, reverts every family,
   reboots, expects the drift audit to exit 3, hardens again and expects the final audit to
   exit 0. Attach `reports/_e2e/<host>/summary.txt` for each release and say which releases
   you ran. Remove host names and addresses you do not want to publish.

3. **A changed control is documented where users will read it**: its entry in
   `controls/catalogue.yml` (what changes, why, impact, how to verify, how to undo), the
   reason in `docs/RATIONALE.md` if a value changes, and the README table if a setting is
   added.

4. **An audit check that changes** says so in `CHANGELOG.md` and bumps `VERSION=` in
   `audit/cis_audit.sh`, because it changes what an old baseline is compared with.

## Ground rules for the code

- A new control must be switchable from the inventory and must be safe as a default on a
  live server. If it depends on the host's role, the default is off or empty.
- Detect the host instead of assuming it. Nothing may depend on a hypervisor, a provider or
  a particular release without a check.
- Anything that can cut the access path belongs inside the guarded stages, and the rollback
  script must be able to undo it.
- An audit check must never pass when it could not read what it checks.

## Reporting security problems

See [`SECURITY.md`](SECURITY.md). Do not open a public issue for them.

Participation is covered by the [code of conduct](CODE_OF_CONDUCT.md).
