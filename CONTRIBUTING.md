# Contributing

1. Open an issue to describe a false positive, missed pattern, or proposed feature.
2. Keep the scanner dependency-free and avoid logging matched credential values.
3. Add an integration fixture for detection changes.
4. Run `node --test test/scan.test.mjs` before opening a pull request.
5. Explain limitations and expected false positives in the README.
