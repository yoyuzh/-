# Risky scanner test inputs

These files are intentionally written with quantum-vulnerable public-key algorithm usages.
They are meant for scanner testing only; you do not need to run them.

Suggested tests:

- Upload all files in this folder through the Web UI.
- Paste one file's content into the snippet input.
- Export the Markdown report and confirm the findings include file names and line numbers.

Expected algorithms include `RSA`, `DSA`, `DH`, `ECC`, `ECDH`, and `ECDSA`.
