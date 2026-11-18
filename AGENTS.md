# Swiftail working rules

Swiftail is a pure Swift tailnet node library intended to replace Tailscale's embedded Go node (tsnet). The plan is in `docs/plan.md`, the protocol notes are in `docs/protocol-notes/`, and the module contracts are in `docs/contracts/`.

- Write docs, code comments, test names, human-readable strings, and commit messages in English. Keep identifiers and protocol terms as in the source. `docs/ko/` holds Korean reference copies of README.md, SECURITY.md, and docs/releasing.md for the owner. When you change one of those three originals, update its Korean copy in the same commit. Reports from agent sessions to the lead are in English.
- Use Swift 6 language mode with strict concurrency and zero warnings. Add documentation comments to public APIs. Write tests with swift-testing.
- Write the entire library in Swift. Do not introduce C or other languages, or external Swift packages. The Go test tools in `Tools/` are the exception.
- Write code that sets an example for Swift developers. Follow [Code Standards in §5](docs/plan.md#code-standards). Use value-type state machines and keep I/O at the edges. Use typed errors, validate inputs at boundaries, follow the Swift API Design Guidelines, and write documentation comments that explain what and why. Do not use unsafe constructs.
- Keep implementations minimal. Do not add abstractions, options, wrappers, or code for future use unless requested. Preserve verification (test vectors and interop tests), input validation at boundaries, and security.
- Verify protocol details in the Go source fetched by `Scripts/fetch-reference-sources.sh` or in `docs/protocol-notes/`. Do not rely on memory. When porting Go code, record its source and license in the file header.
- Build and test with `eyebuild`, for example `eyebuild swift <purpose> -- test`. Artifacts go on the build disk at the path returned by `eyebuild dir <purpose>`. Do not create `.build` inside the repository. When finished, remove the purpose directory you created with `eyebuild rm <purpose>`.
- Keep keys, auth keys, real tailnet and device names, real names, personal email addresses, and `/Users/...` paths out of code, docs, tests, logs, and reports. Use placeholders such as `tail0001`, `rd-mac-1a2b3c4d`, and `100.64.0.1`.
- Compare secrets in constant time. Never log secrets.
- Stay within your assigned files. Report anything that needs fixing outside that scope.
- The repository is public on GitHub. Assume anything you commit will become public on the next push. Treat the adjacent `../remotedebug` repository, home of Swiftail's first adopter, RemoteDebug, as read-only.
- The lead session may push `main` after it passes the gate and may tag and push PATCH releases once the [release conditions](docs/releasing.md) hold. MINOR and 1.0 releases, any action on an existing tag, other pushes, and repository settings changes require the owner's instruction and are reserved for the lead session. Other sessions never push or tag.
- Report anything you could not verify and any failed tests, including their output as-is.
- Only the lead may create or edit files under `_context/`, which holds handoff documents.
