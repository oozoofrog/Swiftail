# Releasing Swiftail

Before 1.0, bump MINOR for any change that can break source compatibility or valid behavior in any product. This includes removing or renaming public symbols, changing signatures, and tightening documented behavior for valid use. Swiftail builds without library evolution, so adding a public enum case breaks exhaustive switches. Bump PATCH for compatible fixes and purely additive API changes.

The lead session may tag and push PATCH releases once the conditions below hold. MINOR and 1.0 releases and any action on an existing tag require the owner's instruction. Other sessions never tag or push.

- [ ] Read the diff since the previous tag and choose the version using the rule above.
- [ ] Update the hard-coded versions in the `README.md` installation example, the `User-Agent` in `Sources/SwiftailCertificates/ACME/URLSessionACMETransport.swift`, its expectation in `Tests/SwiftailCertificatesTests/ACME/URLSessionACMETransportTests.swift`, and the `User-Agent` example in `docs/contracts/SwiftailHost.md`.
- [ ] Pass the local gate with a zero-warning `-warnings-as-errors` build, all unit tests, and local interoperability tests.
- [ ] Confirm that the GitHub CI `push` run on `main` passed for the exact commit SHA to be tagged.

Create an annotated tag without a `v` prefix. Write the English release notes in `<notes-file>` as the tag message and reuse that message for the GitHub Release.

```sh
git tag -a <ver> -F <notes-file>
git push origin <ver>
gh release create <ver> --verify-tag --notes-from-tag
```

Never move or delete a pushed tag. Fix a bad release with a new PATCH release. Do not create a retroactive GitHub Release for `0.1.0`.
