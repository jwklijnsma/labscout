# Development

```bash
make install      # editable install with pytest
make test         # Python tests, including web API tests against a fake Ollama
make web-test     # typecheck and test the UI
make web          # rebuild the UI bundle into src/labscout/web/static/
```

## Web UI

The UI source is in `web/` (React, TypeScript, Vite). The built bundle in
`src/labscout/web/static/` is committed, so `pip install` and the Docker image need no Node.js.
After changing anything in `web/`, run `make web` and commit the result. The `web` workflow
fails when the committed bundle is out of date, and rebuilds it itself on Renovate PRs.

For hot reload, run `make serve` and, in a second terminal, `make web-dev`. The Vite dev server
proxies `/api` to port 8766.

## Screenshots

The images in `docs/assets/screenshots/` come from `scripts/screenshots.py`. It runs the real UI
on made-up sample hosts with the test suite's fake Ollama, and photographs each page in light and
dark mode with Playwright. Regenerate them after UI changes:

```bash
pip install playwright && playwright install chromium
make screenshots
```

## Tests

- `tests/test_labscout.py` covers discovery parsing, fingerprints, the model guard rails and
  cache, state carry-over, the plan, the `apps.yml` patch and NetBox upserts.
- `tests/test_web.py` starts two fake web apps on 127.0.0.1 and 127.0.0.2 and a fake Ollama
  (`tests/mock_ollama.py`). It then runs real scan, identify and plan jobs through the API, and
  checks auth, CSRF, the option whitelist and host edits.
- `web/src/lib.test.tsx` covers filtering, routing, input checks and job labels in the UI.

## CI

| Workflow | What it does |
|---|---|
| `docker` | Tests, then builds the image and smoke-tests it: a CLI scan of a fake app and the web UI. Pushes `ghcr.io/jwklijnsma/labscout` from main and tags. |
| `web` | Typecheck, test and build the UI; checks that the committed bundle matches the source. |
| `docs` | Strict Zensical build, published to GitHub Pages from main. |
| `reviewdog` | actionlint, shellcheck, ruff, hadolint, yamllint and tsc as PR comments. |
| `renovate` / `automerge` | Dependency PRs; patch and minor updates merge on their own once green. |
| `release` / `auto-release` | Version bump, tag, wheel and GitHub release, image `X.Y.Z` / `X.Y`. |

## Releasing

Releases go out on their own after a merged PR, and weekly for dependency updates. The PR
labels `release:minor` and `release:major` pick the bump, and `no-release` skips a merge. To
release by hand:

```bash
make release                 # patch
make release BUMP=minor
make release VERSION=1.0.0
make release-dry-run         # build and test everything, publish nothing
```
