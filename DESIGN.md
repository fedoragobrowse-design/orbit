# Orbit design

Mode: Operate. The visitor completes a task; scanability and consistency beat
expression. Brand lives in precise details.

## Tokens

Ground `#F4F2F7`, surface white `#FFFFFF`, ink plum `#30263F`, evergreen
`#176B58` (go/healthy), pending amber `#946200`, destructive `#A43256`,
secondary text `#655E70`, separators `#DDD7E5`. Focus ring evergreen.
Body measure 65–75ch. All implemented as CSS variables in `apps/web/src/style.css`.

## Layout

A 216px plum rail (brand mark, workspace nav, session footer) beside a content
column capped at 72rem. Panels are 1px bordered surfaces with 12–16px radii;
status is text plus tint, never a bare dot. Cooperative-noticeboard voice:
direct headers, honest states, every empty names its recovery.

## States

Every surface ships loading, empty, error (with retry), offline (stream
disconnect notice), denied (401/403 session-gated), and version states
(task `expected_revision` conflicts). Unavailable backends are explicit:
"Not available in this build" plus the milestone that owns them, never a
disabled control without a reason.
