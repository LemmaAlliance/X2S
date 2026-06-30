# Contributing to X2S

Thanks for taking the time to contribute. X2S is a small, early-stage project (currently alpha), so contributions of all sizes are welcome — bug reports, fixes, docs, and new features.

## Before you start

For anything beyond a small fix, it's worth opening an issue first to discuss the approach. This avoids wasted effort on changes that might not fit the project's direction, especially around the storage format or ACL model, which are core to how X2S works.

## Development setup

### Dependencies

- CMake ≥ 3.15
- libmicrohttpd
- OpenSSL (`libcrypto`)
- A C11 compiler (GCC or Clang)

On Debian/Ubuntu:

```
sudo apt update
sudo apt install build-essential cmake libmicrohttpd-dev libssl-dev
```

### Build

```
cmake -S . -B build && cmake --build build
./build/x2s
```

### Running tests

There's a local end-to-end smoke test script you can run against a running instance (there are a few relevant comments in it though):

```
./e2e_local.sh
```

Start the server first (`./build/x2s`) in a separate terminal, with a clean `x2s_data/` directory if you want a reproducible run. CI runs a more complete test suite (CodeQL, build, and e2e checks) on every PR — make sure your branch passes locally before opening one.

## Making changes

- Keep PRs focused — one logical change per PR is easier to review than several bundled together.
- Match the existing code style (naming, bracing, error handling patterns) rather than introducing a new convention in a single file, although I know my code is not the best.
- If your change affects the on-disk storage format (object metadata layout, index structure, etc.), call that out explicitly in your PR description — this is a breaking change for anyone with existing data and needs to be flagged clearly.
- If your change affects the HTTP API (new endpoints, changed request/response shapes, new headers), update the README's API section in the same PR.
- Add or update a relevant check in `e2e_local.sh` if you're touching auth, object lifecycle, or ACL behavior.

## Commit messages

Write commit messages that describe the *end state* of the change, not the debugging journey. It's fine to iterate locally, but please squash or rewrite history before opening a PR so the log reads as a coherent set of changes rather than a series of in-progress fixes.

## Submitting a pull request

1. Fork the repo and create a branch from `master`.
2. Make your changes, with tests/checks passing locally.
3. Open a PR using the provided template.
4. Be responsive to review feedback — small early-stage project, so turnaround is usually quick.

## Reporting bugs / requesting features

Please use the issue templates. Security-relevant issues should still go through the normal issue tracker for now (there's no separate private disclosure process yet) — just flag clearly in the title/labels that it's security-related.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're expected to uphold it.

## License

X2S is licensed under GPL-3.0. By contributing, you agree that your contributions will be licensed under the same terms.
