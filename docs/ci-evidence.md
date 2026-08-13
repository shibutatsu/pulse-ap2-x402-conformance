# Daily Required CI evidence for the 14-day release gate

The CI workflow runs once per day on the default branch. Each scheduled run executes both supported
Node.js versions, regenerates and verifies the pinned AP2 artifacts, and finishes with the
`Required CI result` job.

After those jobs finish, `Record daily Required CI evidence` adds the public run URL, tested commit,
recording time, and job results to the run summary. It also uploads the same data as
`required-ci.json` for 30 days.

## Count the 14-day window

Issue #17 remains incomplete until 14 consecutive calendar days have a scheduled CI run with a
successful `Required CI result`. Use the run URL from each daily record as the public evidence for
that date. A missing or failed daily run restarts the count.

The weekly Mutation Testing runs must also remain successful during the same 14-day window. Its
public run page and uploaded mutation report are separate evidence; the daily CI record does not
claim that mutation testing ran every day.

Push, pull-request, and manually dispatched runs are useful checks but do not count as the scheduled
daily record. Adding this workflow starts evidence collection; it does not by itself satisfy the
14-day release gate.
