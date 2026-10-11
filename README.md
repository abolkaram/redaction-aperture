# Redaction Aperture

A release copy should disclose exactly what policy permits—not one line more, and not an unexplained black box less.

The owner freezes a public numbered document and a distinct public disclosure policy. Validators fetch both sources, bind their byte digests, and return only the sensitive line indexes plus bounded category codes. The contract rejects incomplete or duplicate classifications, then computes the public complement as contiguous release runs.

The stored result is `CLEAR` when every line may be released and `REDACTED` otherwise. The model identifies policy matches; it cannot construct or alter the release mask. Demo sources are operator-authored fixtures, not independent authorities.

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```

## Live aperture

- Contract: [`0x8eaf2F6c0b82A2D0156FD95a29498C679167251A`](https://explorer-studio.genlayer.com/address/0x8eaf2F6c0b82A2D0156FD95a29498C679167251A)
- Reviewed source: [`cc60df2`](https://github.com/abolkaram/redaction-aperture/tree/cc60df2e7dc924a84ec17ae916b7bfbb2940a605)
- Live record: `AP-1791759199`, state `REDACTED`, release runs `[[0,0],[2,2],[4,5]]`.
- Verification: finalized, majority agree, successful execution, exact deployed-source match.
