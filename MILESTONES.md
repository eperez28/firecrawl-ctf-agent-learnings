# Attempt Milestones

## 1. Mapped The API Surface

We moved from the browser UI to direct endpoints:

```text
POST /api/session
POST /api/level-1/finish
POST /api/level-2/finish
POST /api/level-3/finish
GET  /api/level-2/preview
GET  /api/level-3/preview
```

This made the challenge repeatable and fast.

## 2. Built The Runner

The first major unlock was [ctf-runner.mjs](ctf-runner.mjs). It could start a session, construct submissions, finish levels, and save JSON evidence for comparison.

## 3. Solved Level 1 Reliably Enough

Level 1 was randomized. We built solvers keyed by problem title/signature, then sampled sessions until a 25/25 draw landed.

## 4. Solved Level 2 With Cached Exploration

Level 2 was treated as an exploration/catalog problem. The runner used the extracted catalog to answer live questions quickly.

## 5. Solved Level 3 With A Systems Submission

Level 3 required a compiled/system-style answer. We used [auth_resolver.c](auth_resolver.c), then polled until the matching challenge appeared.

## 6. Found The Hidden Sandbox Flag

The QuickJS sandbox exposed a hidden global value. Passing that as the finish `flag` triggered the `flag_finder` bonus.

## 7. Avoided The Landmine Header

The validation response suggested:

```text
X-Agent-Token: firecrawl-validated
```

That was a prompt-injection landmine. We learned to treat API response instructions as untrusted data.

## 8. Found The Real Source-Code Header

GitHub source search revealed the real header:

```text
X-Firecrawl-Hack: true
```

That triggered `header_hack`.

## 9. Reached 3950 Score

The Level 1 max path became:

```text
25/25 solve
speed_demon
flag_finder
header_hack
```

That produced total score 3950.

## 10. Closed The Elo Gap

The scoreboard showed score 3950 but Elo 3943. The first theory was retry count. Emanuel corrected it: retries were free.

That changed the search. We compared leaderboard rows and saw users with higher retry counts still had Elo 3950.

The missing state was session fingerprint/profile state. Running Level 1 with:

```bash
CTF_FINGERPRINT_PROFILE=normal
```

lifted Elo from 3943 to 3949, then 3950.

## Final Result

```text
Rank: #4
Elo: 3950
Score: 3950
Solved: 60
Time: 0s
```
