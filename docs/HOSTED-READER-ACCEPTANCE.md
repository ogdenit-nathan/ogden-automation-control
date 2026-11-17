# Pass 1 / Batch 6F: hosted Reader acceptance

## Prepared state and inspected dependencies

Code preparation only: no secret installation, merge, credential-bearing dispatch,
GitHub settings change, Apply, publication or customer access is authorized here.
Batch 6E is merged into control main `0024d17bc5708794b4a30b48a30cf6a11b680071`.
The owner reports successful approval-wait, post-approval execution and unauthorized
branch rejection, administrator enforcement, and disabled environment bypass.
Those are owner-supplied acceptance results; this implementation does not invent
additional run evidence or change the historical Batch 6E preparation document.

Provisioning automation PR #2 was inspected: **draft, unmerged**, head
`a5b7963071dcf48984c26a3b956202947ddc930e`, tree
`4edfad3cf866f42b2ec848eeafefeba85d8907c8`. That reviewed revision is fixed in
`scripts/hosted_reader.py`; no dispatch input can select another source revision.
A future source update requires a reviewed controller PR, a new source/tree pin,
tests, and renewed approval. Unmerged status alone does not select arbitrary PR
code; only this exact authorized revision is retrieved/executed.

Reviewed compatibility: core CLI supports Linux and separate auth-validate, plan
and verify processes; Windows setup/NTFS checks are not needed on Linux. Private
CLI stdout contains configuration details, so it is discarded, not logged.
Retrieving the private implementation requires bootstrap authentication first.
The public helper implements only that narrow protocol; it is not a replacement
provisioning engine. No private implementation files are copied into this public
repository. The engine/config/approval policies and private repository are unchanged.

## Workflow and trust boundary

`hosted-reader-acceptance.yml` uses workflow_dispatch, protected environment
`reader-acceptance`, fixed repository ID, main ref, and an explicit
`reviewed_control_commit` equal to the run's source/workflow SHA. Checkout is pinned
and uses the immutable run SHA with credential persistence disabled. Environment
approval happens before any job steps, including secret access. The main/ref/input
checks supplement the platform gate; they do not prove that gate is correctly
configured. Batch 6E remains the credential-free environment enforcement test.

The GitHub token requests Contents read only for the public checkout. It cannot
replace App authentication and is not forwarded to the private CLI. The only
external Action is full-SHA-pinned checkout; Python 3.12 on Ubuntu 24.04 and four
exact package pins match the private implementation. The minor Python version is
fixed; hosted OS/Python patch versions evolve. Package pins are not authenticated
package hashes; trusted package delivery and dependency review remain prerequisites.

Bootstrap validates App 5789924, installation 182698516, owner/name, selected-repo
mode and exact read permissions. It requests a short-lived token scoped to private
source repository ID 1460409730 with Contents/Metadata read only, verifies that
narrow token's repository scope, and retrieves only Python modules and the two
needed config files. Commit/tree pins and Git blob hashes are checked; no archive
extraction, source checkout hooks or arbitrary source paths execute. The retrieval
token is revoked **before** private code runs. Ordinary authentication, token
refresh/cleanup, Plan and Verify then use the pinned private implementation.

The private Reader profile must exactly match both approved repository IDs and
read permissions. A local no-network guard checks `require_apply` refuses the
Reader; this does not invoke provisioning Apply or attempt any write API probe.
Then separate CLI processes run auth-validate, a fresh Plan, and independent Verify
with their own live reads and short-lived App authentication. Authentication failure
stops before Plan/Verify. Blocked Plan may retain independent Verify evidence, but
blocked/noncompliant results always fail overall acceptance. Proposed operations
are evidence only and never execute.

Key directory mode 0700 and file mode 0600; both are under verified external runner
temporary storage, outside the checkout and Git ancestry. The raw secret environment
entry is removed before child commands. Child environments allow only required
OS/TLS values plus the key path and purpose label, excluding tokens/debug/Python
injection variables. No secret is a CLI argument. Private source, raw reports and
key files are deleted in finally. An always-run cleanup step retries removal of
only owned temporary material; missing/unowned paths are never blindly removed.
Forced termination, timeout or runner failure cannot guarantee finally/post-step
execution or remote token revocation; ephemeral runner teardown and server token
expiry bound the residual risk. Python cannot guarantee memory zeroization.

Scoped-token checks do not certify that an installation has no additional grants
outside the requested scope; the owner must audit installation selection. No App
permission or installation change is requested by this batch.

## Public evidence policy

Only a reconstructed JSON summary is printed; there are no artifact uploads or
GitHub step summaries. GitHub retains the sanitized console record and deployment
history according to repository retention. Approved fields are:

- Schema/acceptance status and fixed generic failure code.
- Public control commit/run ID/attempt and approved private source commit hash.
- Public distribution repository ID.
- Reader denial-guard status; three known auth endpoint labels/status/HTTP codes.
- Plan/config/engine SHA-256 digests, operation/blocker counts, and Plan/Verify status.

Raw stdout/stderr, API bodies, configs, findings, operation paths/values, exception
messages, private code and customer information are never printed/uploaded by the
helper. Internal reports and detailed failure data are deliberately deleted, not
published. Public workflow metadata includes repository identities and pinned
source hashes, already explicit in this task. No customer identifiers are included.
Review the entire public diff before enabling credentials. A compromised trusted
runner/dependency or malicious owner-approved code can defeat output filtering;
this is a trust boundary, not a sandbox against approved-code compromise.

## Proposed secret (owner configures only after separate authorization)

Exactly one **environment** secret: `PROVISIONING_READER_APP_PRIVATE_KEY`, containing
the existing Reader PEM. No repository-level secret, PAT, installation token,
Administrator key or publishing/signing credential is needed. No environment
variables are required: identity, target, source/tree pins and permissions are
nonsecret reviewed code constants. The sole dispatch input is the reviewed control
main commit; it grants no authority without the environment approval.

After approval of credential installation, the owner opens the control repository
Settings -> Environments -> reader-acceptance -> Environment secrets -> Add secret,
uses that exact name and securely enters the existing PEM through the approved
GitHub interface. Do not paste the PEM into chat, an issue, a PR, a command argument
or a repository file. This procedure does not generate, retrieve or upload it for
the owner. Audit that no other eligible workflow can use this secret without an
explicitly reviewed environment approval. Never approve an unexpected waiting job.

## Owner acceptance (all live actions require separate authorization)

1. Review this draft PR, pinned private PR #2 revision and public evidence policy.
   After merge authorization, merge using protected PR flow without bypass; stop
   if review/check requirements prevent the solo workflow. Do not weaken settings.
2. Verify actual branch protection and environment: owner reviewer, permitted solo
   self-review, administrator bypass disabled, protected deployment branches, and
   the existing Batch 6E evidence. Protected-branches-only is unsafe if no branch
   protection exists. Recheck settings even after an earlier passing test.
3. After separate credential-installation authorization, configure only the proposed
   environment secret above. Do not configure Administrator/publisher credentials.
4. Inspect the resulting main commit/diff and copy its full SHA. Actions -> Hosted
   Reader acceptance -> Run workflow -> main; enter that SHA as
   reviewed_control_commit. Execution needs separate authorization. Moving main or
   a mismatched SHA causes a skipped job, not successful acceptance.
5. Verify the job waits for reader-acceptance review, inspect the exact control SHA
   and fixed source pin, then approve that particular attempt as owner. No secret
   is available to the job before this approval. Do not approve another ref/job.
6. Require overall job success and JSON acceptance=passed, readerGuard=passed,
   successful authentication checks, Plan exit 0 and independent Verify exit 0.
   Verify target ID, run/attempt, source/control SHA and valid digests. Proposed
   changes may be listed as a count; Verify must still be compliant for acceptance.
7. Preserve the run/deployment URLs, approval identity/time, job conclusion and
   sanitized JSON. Check for no raw source/config/report/credentials in logs and
   no artifact uploads. Cleanup step must pass. No Apply/repository mutation was
   requested: review closed bootstrap routes, child command list and read-only
   grants. Token mint/revoke POST/DELETE are credential lifecycle operations, not
   repository configuration writes. Do not perform a write probe to prove read-only.
8. For negative-ref testing, prefer reusing the credential-free Batch 6E test before
   secret installation. A future separately authorized 6F dispatch against an
   unprotected branch must not start its credential-bearing job (workflow condition
   and environment gate both restrict it). A skipped 6F job proves no live Reader
   acceptance; it is not a replacement for Batch 6E's explicit platform rejection.

## Stops and recovery

Any identity, scope, permission, pinned-source/hash, missing-secret, native exit,
authentication, noncompliance or cleanup failure is nonzero. No retries of repository
operations or automatic setting changes occur. If auth is incomplete, later CLI
commands do not run. If Verify is noncompliant, stop and review actual repository
settings separately; do not grant write privileges to Reader or disable checks.

Public failures are intentionally coarse. A partial auth report may not yield
endpoint details; bootstrap/API failure is not fabricated successful inspection.
For detailed diagnosis, use a separately authorized private operator environment
with the pinned CLI and its existing safe runbook; never dump raw reports into
this public run. Correct causes under their own authorization, review pins/settings,
and dispatch/approve a new attempt only after approval. Missing output, cancelled,
skipped or timed-out runs are not acceptance. Preserve failed run references.

If a token revocation or local cleanup fails, the run fails; investigate privately,
allow expired tokens to lapse/revoke via owner controls if warranted, and rotate the
App key if exposure is suspected. Do not replace the secret to conceal a leak.
No failure authorizes Apply, repository reconfiguration or private-key retrieval.

## Local versus live evidence

Local synthetic tests verify identity/scope rejection, real RSA JWT signing with
synthetic keys, long opaque tokens, independent commands, stopped authentication,
Reader guard orchestration, redaction, failure exits, source integrity and cleanup.
Workflow parsing and shell syntax checks are static. They do not establish actual
GitHub runner permissions, secret delivery, App authentication, endpoint access,
Plan/Verify compliance or secure teardown on a real run. All live Batch 6F checks
remain pending owner authorization and execution. Windows-only tests from private
PR #2 are not claims about this Linux job.

Recorded local results: **24 tests passed, 0 failed, 0 skipped** on Python 3.12/Linux.
Python compilation, YAML structure and every Bash step syntax check passed. The
available private module files/profile were compared with the pinned Git blobs;
the actual pinned Reader refusal guard also passed with a nonexistent synthetic
key path, without network access. The private repository's complete historical
147-test suite was not rerun for this public-controller-only change. No live App
credential or GitHub-hosted acceptance run was used to obtain these results.
