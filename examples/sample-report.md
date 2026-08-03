# DocRedact report: sample.txt

Local-first extraction and detection. Fully offline; no network calls.

- Format: `txt`
- SHA-256: `e53ea853e6bcd000b7a38d0410b2679cb55b4c4d513097d53f5344fb869e7e62`
- Size: 333 bytes, 4 blocks
- Findings: 6 (critical 2, high 1, medium 1, low 2)
- Redaction mode: `report`

## Findings

| Severity | Confidence | Type | Block | Value | Reference |
| --- | --- | --- | --- | --- | --- |
| low | high | email | 1 | `jane.doe@example.com` | CWE-359 privacy violation (contact PII) |
| low | high | phone | 1 | `+1-555-0142` | CWE-359 privacy violation (contact PII) |
| high | high | credit_card | 2 | `4111111111111111` | CWE-312 cleartext storage of card data (PCI) |
| critical | high | api_key | 2 | `AKIAIOSFODNN7EXAMPLE` | CWE-798 hardcoded credentials |
| critical | high | pem_key | 3 | `-----BEGIN RSA PRIVATE KEY-----` | CWE-798 hardcoded credentials |
| medium | medium | high_entropy | 3 | `bm90IGEgcmVhbCBrZXkgLSBmaXh0dXJlIG9ubHk=` | CWE-312 cleartext storage (suspected secret) |

## Sanitized artifact

Written to `sample-safe.txt`.

| Token | Type | Occurrences |
| --- | --- | --- |
| `[EMAIL_1]` | email | 1 |
| `[PHONE_1]` | phone | 1 |
| `[CREDIT_CARD_1]` | credit_card | 1 |
| `[API_KEY_1]` | api_key | 1 |
| `[PEM_KEY_1]` | pem_key | 1 |
| `[HIGH_ENTROPY_1]` | high_entropy | 1 |
