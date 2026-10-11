# Redaction Aperture

A release copy should disclose exactly what policy permits—not one line more, and not an unexplained black box less.

The owner freezes a public numbered document and a distinct public disclosure policy. Validators fetch both sources, bind their byte digests, and return only the sensitive line indexes plus bounded category codes. The contract rejects incomplete or duplicate classifications, then computes the public complement as contiguous release runs.

The stored result is `CLEAR` when every line may be released and `REDACTED` otherwise. The model identifies policy matches; it cannot construct or alter the release mask. Demo sources are operator-authored fixtures, not independent authorities.

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```
