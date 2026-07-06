# Releasing Airlock to the GitHub Marketplace

Technical prep for publishing the Action. The actual publish (checking the
"Publish to Marketplace" box) is a manual step on the repo owner's account —
see the checklist at the end.

## Prerequisites (one-time)

- The Action lives in its **own public repo** whose root contains `action.yml`
  (it does here). Marketplace requires the metadata file at the repo root.
- `action.yml` has a **unique `name`** across the Marketplace, plus `description`
  and `branding` (icon + color) — all present.
- Repo has a `README.md` (present) and a `LICENSE` (present, MIT).
- Two-factor auth is enabled on the owner account (Marketplace requires it).

## Versioning model

Follow the GitHub Actions convention: semver tags **plus a floating major tag**
so consumers can pin to `@v1` and get non-breaking updates automatically.

```bash
# cut a release
git tag -a v0.1.0 -m "Airlock v0.1.0"
git push origin v0.1.0

# move (or create) the floating major tag to the same commit
git tag -f v1 v0.1.0
git push origin v1 --force
```

- Consumers reference `SEU_USUARIO/airlock@v1` (recommended) or pin exact `@v0.1.0`.
- **Breaking change** → bump the major and start a new floating tag (`v2`).
  Never repoint `v1` at a breaking commit.
- Keep the `version` in `package.json` in lockstep with the tag.

Suggested flow per release:

1. Update `version` in `package.json`.
2. Update `CHANGELOG` notes (or the GitHub Release body).
3. Tag `vX.Y.Z`, push.
4. Force-move the floating `vX` tag, push.
5. Create a GitHub Release from `vX.Y.Z` (this is also the Marketplace listing trigger).

## Publish checklist (manual — repo owner)

1. Repo → **Releases** → **Draft a new release**.
2. Choose the `vX.Y.Z` tag.
3. Check **"Publish this Action to the GitHub Marketplace"**.
4. Accept the Marketplace agreement (first time only).
5. Pick primary + secondary categories: **Continuous integration** / **Security**.
6. Confirm the icon/color preview (from `branding` in `action.yml`).
7. Publish the release.

## Notes / future hardening

- **Startup speed:** the composite action runs `npm install` at runtime. Fine for
  the MVP. To make cold starts instant, bundle to a single file with `@vercel/ncc`
  and switch `action.yml` to a Node action (`runs.using: node20`, `main: dist/index.js`).
- **Supply chain:** pin `actions/setup-node` to a commit SHA before publishing widely.
