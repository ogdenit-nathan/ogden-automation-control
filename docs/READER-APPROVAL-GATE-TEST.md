# Batch 6E: credential-free approval-gate acceptance

Target: `ogdenit-nathan/ogden-automation-control` (public, repository ID 1460643831).
Environment: `reader-acceptance`. Workflow: `.github/workflows/reader-approval-gate-test.yml`.

## Status and scope

Prepared only. No workflow was dispatched or approved, and no merge/settings change
was performed by Codex. Approval enforcement is **not verified**. Owner reports
required reviewer `ogdenit-nathan`, permitted self-review, no administrator bypass,
protected-branches-only deployment, no environment secrets/variables, read-only
default token permissions, and SHA pinning. Codex confirmed repository visibility,
default branch and initial contents. Branch-protection API inspection returned
HTTP 403, `Resource not accessible by integration`; no enforcement was inferred.

The job prints only its run ID, source SHA and a fixed execution message. It has
no inputs, secrets, checkout, third-party Actions, artifacts, API requests or
external deployments. `permissions: {}` requests no optional workflow-token
permissions (GitHub retains platform-defined metadata access). The automatic
GitHub token is neither referenced nor printed. GitHub's standard runner/setup
logs are platform-generated and are not additional scripted diagnostics.

The environment declaration creates a GitHub deployment record; it does not
deploy software. There is deliberately no `if: github.ref == ...` condition:
otherwise a skipped job could conceal a missing environment branch restriction.
There are no `uses:` steps, so full-SHA Action pinning has no dependencies to pin.

## Owner prerequisites (separate authorization required)

1. Review the draft PR and exact commit. Do not merge or dispatch until separately
   authorizing those actions. This document itself does not grant that approval.
2. In Settings, inspect `reader-acceptance`: reviewer is the owner; self-review
   permitted; **Allow administrators to bypass configured protection rules** is
   unchecked; deployment uses protected branches only. Confirm actual main branch
   protection and the intended eligible branches. Do not change settings for this
   test. Missing/incorrect controls mean stop and report.
3. Confirm there are still no secrets/variables. Keep this repository and run free
   of production credentials. Review all workflow bytes and pinned source commit.
4. If authorized, merge through the protected PR process without bypass. If a
   review/check requirement prevents a solo owner from merging, stop; do not weaken
   protection or use a direct push. Retain the development branch for the negative
   test. Record the resulting main commit SHA, which may differ from the PR commit.

`workflow_dispatch` must exist on the default branch before the normal manual
Actions UI is usable. Do not use a push/PR trigger as a shortcut. GitHub requires
write access for manual dispatch; dispatch permission is not environment approval.
See [manual workflow execution](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

## Acceptance procedure (owner executes only after authorization)

### 1. Before approval

Actions -> **Credential-free Reader approval gate test** -> Run workflow -> branch
`main`. Record the run URL/ID, attempt number, ref, source SHA and dispatch time.
Do not approve yet. Observe the protected job waiting for review at two times at
least one minute apart. Verify its diagnostic step has no start/completion time
or execution log. Do not confuse a runner queue delay with **waiting for environment
review**. Unexpected step execution before approval is a failure: stop/cancel and
preserve evidence; do not proceed to credential-bearing tests.

### 2. Authorized approval and successful execution

Sign in as `ogdenit-nathan`, open **Review deployments**, select `reader-acceptance`,
and approve the expected run. Self-review by the dispatching owner is intentional.
Record reviewer, approval time, job/step start time and conclusion. Require:

- The waiting job was released by the recorded owner approval.
- Diagnostic execution begins after approval and completes successfully.
- The log's run ID and SHA match this run and the reviewed main revision.

A printed execution message alone does not prove approval. Correlate deployment
history, job timestamps and logs. A successful old run or approval for another
attempt is not evidence for the current attempt.

### 3. Unauthorized branch rejection

Keep the merged workflow present on main. Confirm the retained development branch
is **not protected/eligible** for this environment and still contains the reviewed
workflow. Dispatch the same workflow with that development branch selected. Its
ref/SHA will differ from the positive test. Do not approve or attempt a bypass.
Require an explicit GitHub environment branch-policy rejection and no diagnostic
step execution. Waiting for review alone, skipping the job, or an unrelated error
is **not a passing branch-restriction test**.

If that branch is protected/eligible, it is not a valid negative test. Stop and
report the limitation; creating a new test ref needs separate authorization.
Protected-branches-only allows every eligible protected branch, not just main.
GitHub also documents that this policy allows all branches if no branch protection
rules exist. Verify effective branch protection, not only the dropdown label.
See [deployment branches and bypass controls](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

### 4. Administrator bypass

Record the owner-visible environment configuration showing administrator bypass
is disabled and, while the positive run waits, that an administrator cannot use
an available **Start all waiting jobs** bypass control. Do not enable bypass or
actually bypass the gate to test it. Distinguish configuration/UI verification
from an adversarial bypass attempt, which this procedure does not perform.
An inability to inspect the setting is **unverified**, not a pass. The connector's
403 is a permission limitation, not evidence that bypass is disabled.

## Evidence record (complete after actual runs)

Use GitHub run/deployment links and harmless screenshots or timestamps. Do not add
credentials, private reports or customer identifiers. Record positive and negative
attempts separately; public logs are public.

| Check | Expected | Actual / evidence URL and timestamps | Result |
| --- | --- | --- | --- |
| Main holds before approval | Waiting for environment review; no diagnostic execution | Not run | Pending |
| Owner approval | Correct owner releases the exact waiting attempt | Not run | Pending |
| Post-approval execution | Successful step after approval; matching run ID/SHA | Not run | Pending |
| Unprotected branch | Explicit environment branch rejection; no step execution | Not run | Pending |
| Admin bypass disabled | Setting disabled; no usable bypass UI | Owner-reported only | Unverified |

Record issue/run references and any cancellation, rerun, unexpected configuration
or unavailable UI. Do not overwrite failed evidence with a later successful run.
Only mark overall acceptance passed when all required checks have adequate evidence;
label the bypass test's configuration/UI scope explicitly.

## Security limits

This tests a GitHub Free **public** environment, not private-repository reviewer
availability. It does not validate App authentication, secret isolation, provisioning
Apply, release signing/publication, workstation updates or customer access. No such
capabilities are added. Platform settings can change after acceptance; recheck before
introducing credentials. An administrator can change settings with separately
held authority; disabling runtime bypass does not remove that administrative power.
The harmless message deliberately does not assert that a real owner approval occurred.
No second account, denial/rejection path, protected-tag path, forced bypass, or malicious
workflow modification is exercised by this minimal test. No app keys or additional
credentials should be added as part of Batch 6E.
