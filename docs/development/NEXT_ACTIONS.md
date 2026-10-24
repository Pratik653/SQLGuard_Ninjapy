# Next actions (development program)

1. SQL Server/Oracle real-database tests need vendor licence acceptance (maintainer decision); MySQL function/catalog cases stay under #5.
2. Merge the v0.7.0 PR after CI (demo e2e + container jobs); add both jobs to required checks; release; verify PyPI + fresh `[demo]` install and `sqlninja demo serve`.
3. Phase 8: public hosting needs maintainer authorization: enable GitHub Pages (Source: GitHub Actions), then run `pages.yml` and verify the real HTTPS URL in an unauthenticated browser.
