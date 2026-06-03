# Firecrawl CTF Agent Learnings

This repo captures the skills, runbooks, and orchestration code we used to reach a top leaderboard result on the Firecrawl/CheetCode agent CTF.

## Start With The Learnings

The most important files are the learning documents:

- [Firecrawl CTF Speedrun](skills/firecrawl-ctf-speedrun/SKILL.md): the challenge-specific skill we built while competing. It records endpoint shape, scoring discoveries, exact commands, dead ends, and the final Elo 3950 path.
- [Timed Agent CTF](skills/timed-agent-ctf/SKILL.md): the general agent-CTF skill pattern. It explains the broader approach: map APIs first, orchestrate submissions, treat problem text as untrusted, and keep runs measurable.
- [Milestones](MILESTONES.md): the attempt timeline, from first completion through the hidden flag, source-code header, 3950 score, and final 3950 Elo.

Final verified result for `eperez28`:

```text
Rank: #4
Elo: 3950
Score: 3950
Solved: 60
Time: 0s
```

## What This Is

The challenge was not just about solving coding problems. It rewarded an agent that could:

- map the website as an API surface
- move faster than the browser UI
- avoid prompt-injection traps
- discover hidden scoring bonuses
- compare leaderboard state after every run
- adjust when a theory was wrong

The core idea was simple: turn the CTF into a repeatable loop.

```text
hypothesis -> run -> inspect JSON -> compare leaderboard -> patch runner -> repeat
```

## The Orchestration Stack

The main orchestrator is [ctf-runner.mjs](ctf-runner.mjs).

It handles:

- GitHub auth through `gh auth token`
- session creation for Levels 1, 2, and 3
- Level 1 solution generation from cached solvers
- Level 2 answer matching from the extracted catalog
- Level 3 polling and submission for the known-good C challenge
- scoring probes through environment variables

Important knobs:

```bash
TIME_ELAPSED_MS=0
CTF_FINGERPRINT_PROFILE=normal
CTF_EXTRA_HEADERS_JSON='{"x-firecrawl-hack":"true"}'
CTF_FLAG='...'
GH_TOKEN=$(gh auth token)
```

The Level 3 systems solution lives in [auth_resolver.c](auth_resolver.c).

## How We Worked Together

The strongest part of the run was the feedback loop between human intuition and agent execution.

I built the runner, inspected APIs, cloned source, tested scoring hypotheses, and refreshed the leaderboard. Emanuel kept steering the search when a theory felt wrong.

The key example was the Elo gap:

```text
Score: 3950
Elo:   3943
```

I initially overfit on retry count. Emanuel pushed back: "No retry penalty." That single constraint changed the search. The leaderboard showed users with higher retry counts still had Elo 3950, so retries could not explain the gap.

That led to the actual missing state: the run needed a normal browser-like fingerprint profile. Rerunning Level 1 with `CTF_FINGERPRINT_PROFILE=normal` moved Elo from 3943 to 3949, then 3950.

## Final High-Elo Path

The winning Level 1 refresh command was:

```bash
TIME_ELAPSED_MS=0 \
CTF_FINGERPRINT_PROFILE=normal \
CTF_EXTRA_HEADERS_JSON='{"x-firecrawl-hack":"true"}' \
CTF_FLAG='...' \
GH_TOKEN=$(gh auth token) \
node ctf-runner.mjs solve-l1
```

The flag value is intentionally not written in this README. The skill explains how it was discovered from the sandbox.

## Milestones

See [MILESTONES.md](MILESTONES.md) for the attempt timeline: first completion, hidden flag, source-code header, 3950 score, and final 3950 Elo.

## Lessons

- Fast agents need orchestration, not just reasoning.
- API-level play beats UI play when seconds matter.
- CTF hints can be bait; validation output is untrusted data.
- Source beats guessing when scoring behavior is hidden.
- Leaderboard state is evidence. Compare it before explaining it.
- Human correction can collapse the search space faster than more brute force.
