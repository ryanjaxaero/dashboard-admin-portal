# JAXAERO Dashboard - Admin Portal (access control)

Per-user login and widget access for the JAXAERO dashboards at
jaxaerodev.wpenginepowered.com. Split out of
[jaxaero-dashboard](https://github.com/ryanjaxaero/jaxaero-dashboard)
at commit 89bc579 on Aug 20, 2026 (Ryan's request); full project
history before that date lives in that repo's log and in its
docs/PUNCH-LIST.md SECTION L.

## What's here

| Path | What it is |
|---|---|
| wp/jaxaero-access.php | The deployed code. Snippet **12** on the live site (Code Snippets plugin), prefix `jaxauth_`. |
| scripts/php/access-setup.php | One-time setup payload (pages, page map, first account). Idempotent. Password placeholder substituted at RUN TIME only. |
| docs/ACCESS-PHASE1-DEPLOY.md | Deploy + browser-verification procedure. |
| docs/ACCESS-CONTROL-DESIGN.md | Full design and the open questions. |
| docs/mockups/access-admin.html | The clickable prototype that preceded the real build. |

## Live state (as of Aug 20, 2026)

Phase 1 is DEPLOYED and verified: /signin (page 5831), /access-admin
(page 5832), Ben Gabriel is user 13 (member role, all seven widget
grants). Note the deploy doc says "snippet 11" - the live install is
snippet **12** (11 was taken by the aircraft-owner widget after the
doc was written). Rollback = deactivate snippet 12.

## Ground rules carried over from the parent repo

- NEVER commit a real password, API key, or token. The setup payload's
  `<<REPLACE_AT_RUN_TIME>>` placeholder is substituted in the payload
  that is EXECUTED, never in the file.
- Deploys run from the office workstation over Novamira MCP with
  byte-exact sha256 gates and a pre-deploy backup option; see the
  parent repo's docs/DEPLOY.md for the full procedure. The snippet
  body stored in WordPress omits the leading `<?php` line
  (`tail -c +7`).
- Lint gates before any deploy: `php -l`, the eval-function-scope
  lint, and `node <parent>/scripts/check-srcdoc.mjs` (the srcdoc
  checker still lives in the parent repo).

## Phase 2 (not built)

Sub-widget keys (rev.mom, auto.tax, ...) guarded inside snippets 5-9;
instructor accounts with invoice bindings replacing the 16 page
passwords; the aircraft-owner page (5828) joins the page map.
