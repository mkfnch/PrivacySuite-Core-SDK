# Ramifications of Extending PrivacySuite Core SDK with a Blind Index API

## Research Summary

This document analyzes the architectural, security, and operational ramifications of
adding a blind index API to the PrivacySuite Core SDK.

---

## 1. What Is a Blind Index?

A blind index is a truncated, keyed cryptographic hash (typically HMAC) of plaintext
data, stored alongside encrypted ciphertext. It enables **exact-match queries on
encrypted data** without decrypting the entire dataset.

**Workflow:**
1. **On write:** Compute a keyed hash (e.g., HMAC-SHA256) of the plaintext, truncate
   to a configured number of bits, and store as a separate column alongside the
   encrypted ciphertext.
2. **On query:** Compute the same keyed hash of the search term, truncate identically,
   and issue a standard database equality query against the blind index column.
3. **Post-filtering:** Because truncation introduces deliberate false positives,
   decrypt returned rows and filter non-matches client-side.

The blind index key is held only by the application; the database never sees plaintext
or the full hash.

---

## 2. Architectural Fit with Existing SDK

### Available Primitives

| Requirement                  | Already Available in SDK                                  |
|------------------------------|-----------------------------------------------------------|
| HMAC-SHA256/SHA512           | `hmac` (0.12) + `sha2` (0.10)                            |
| Keyed hashing (modern)       | `blake3` (1) — supports native keyed mode                |
| Slow hashing (low-entropy)   | `argon2` (0.5) — already used for vault key derivation    |
| Key derivation               | BLAKE3 `derive_key` or potential `hkdf` addition          |
| Randomized AEAD encryption   | XChaCha20-Poly1305 in `crypto/aead.rs`                    |
| Encrypted storage            | SQLCipher in `storage.rs`                                 |
| Zeroization                  | `zeroize` (1.7) — pervasive across all key types          |
| Constant-time comparison     | `subtle` (2) — used in mnemonic validation, key equality  |

### Module Placement

A new `src/crypto/blind_index.rs` module would fit naturally alongside the existing
crypto primitives (`aead.rs`, `keys.rs`, `mnemonic.rs`, `pairing.rs`). Integration
with `storage.rs` would provide SQLCipher-aware helpers for index column management.

### Dependency Impact

Minimal. All required cryptographic primitives are already in `Cargo.toml`. The only
potential addition is `hkdf` for formal HKDF key derivation, though BLAKE3's
`derive_key` could serve the same purpose. The `deny.toml` supply chain policy remains
intact.

---

## 3. Tension with the Zero-Knowledge Promise

### The Core Guarantee

The SDK's foundational promise is:

> "Structurally impossible to store plaintext user data outside the user's device."

A blind index is a **deterministic, one-way derivative of plaintext**. It leaks
equality — identical plaintexts always produce identical index values. This is a
fundamental departure from the current posture where:

- All encryption is randomized (XChaCha20-Poly1305 with random nonces)
- No deterministic artifact of plaintext exists anywhere
- The server relay sees only opaque encrypted blobs

### Implications by Deployment Scope

**Local-only (SQLCipher):** If blind indexes are stored exclusively in the local
encrypted database, the zero-knowledge posture is **preserved**. The device already
has plaintext access; the blind index adds no new information exposure.

**Server-synced:** If blind indexes are transmitted to a server for remote search, this
**breaks the zero-knowledge model**. The server gains deterministic derivatives of
plaintext, enabling frequency analysis and inference attacks. This would be equivalent
to a fundamental change in the SDK's threat model.

### Recommendation

Scope the initial API to **local-only** blind indexing (querying the local SQLCipher
database). Server-side searchable encryption is a fundamentally different threat model
requiring separate, careful design with distinct documentation.

---

## 4. Security Risks Introduced

### 4.1 Frequency Analysis (Primary Risk)

Identical plaintexts produce identical blind index values. An attacker with database
access can count value frequencies and correlate against known distributions.

**High-risk fields:**
- Low-cardinality: booleans, status codes, gender, yes/no medical results
- Skewed distributions: country codes, common surnames, age ranges

**Mitigations:**
- Truncation (deliberate false positives — multiple plaintexts share an index value)
- Compound indexes (combine multiple fields before hashing)
- Slow hashing (Argon2id) for fields with small input domains
- Partitioned indexes (per-user or per-context keys prevent cross-partition correlation)

### 4.2 Chosen-Plaintext Attacks

If a user of the application can insert known values and observe the resulting blind
indexes (e.g., via SQL injection or being a legitimate multi-tenant user), they can
enumerate the entire input domain by inserting every possible value and correlating
with existing index entries.

### 4.3 Cross-Index Correlation

Multiple blind indexes on related fields (e.g., City + ZIPCode) can be cross-correlated
to narrow down actual values, even when individual indexes have high false-positive
rates. AWS documentation specifically warns about this.

### 4.4 Brute-Force on Key Compromise

If the blind index key leaks (but not the encryption key), an attacker can compute the
keyed hash for all possible values of low-entropy fields. This is why slow hashing
(Argon2id) is essential for fields with small input domains — it makes brute-force
enumeration computationally expensive.

### 4.5 Compound Leakage

Having many blind indexes (100+) on a single field compounds leakage. CipherSweet's
coincidence formula quantifies this:

```
C = R / 2^(sum(min(L_i, K_i)))
```

Where `L_i` is each index's output bits, `K_i` is input domain bits, and `R` is row
count. Safety requires `2 <= C < sqrt(R)`.

---

## 5. Key Management Implications

### New Key Hierarchy Tier

- Blind index keys **MUST** be distinct from encryption keys (enforced by CipherSweet,
  AWS SDK, and Acra).
- Each field/index should derive its own key from a master blind index key via
  HKDF or BLAKE3 `derive_key` with a unique context string.
- The existing `VaultKey` derivation in `crypto/keys.rs` needs extension: either a
  second derivation path from the passphrase, or a separate key stored in the vault.

### Key Rotation

Key rotation for blind indexes is significantly more expensive than encryption key
rotation:

- **Encryption rotation:** Decrypt with old key, re-encrypt with new key (per-row).
- **Blind index rotation:** Decrypt all rows, recompute every index value with the new
  key, update all index columns.

This requires:
- Key version metadata in the index schema
- Dual-read support during migration (query both old and new index columns)
- Background re-indexing with progress tracking

AWS SDK sidesteps this entirely by only supporting blind indexes on new databases.

### Impact on Mnemonic Recovery

If blind index keys are derived from the same BIP39 root as the `VaultKey`, mnemonic
recovery automatically restores search capability. If they are independently generated,
a separate backup mechanism is needed. **Recommendation:** Derive from the same root
with a distinct context string.

---

## 6. Performance Considerations

| Operation                         | Expected Overhead                                |
|-----------------------------------|--------------------------------------------------|
| Write (fast HMAC-SHA256/BLAKE3)   | Sub-millisecond per field                        |
| Write (slow Argon2id, low-entropy)| 50–200ms per field (tunable)                     |
| Query                             | 1 HMAC + SQLite index lookup + decrypt false positives |
| Storage                           | 4–32 bytes per index per row                     |

### Mobile Considerations

The SDK targets mobile ARM with Argon2id parameters of m=64MB, t=3, p=4 for vault
unlock. Blind index computation with Argon2id happens on **every write** (not just
vault unlock), so lower parameters are appropriate for the slow-hash path. Benchmarking
on target hardware is essential.

### Benchmarks from Literature

- BlindexTEE reports 36%–462% overhead vs. unencrypted database access.
- Practical systems report millisecond-range search latency on million-row datasets
  (the database B-tree lookup dominates, not the HMAC computation).
- False positive rates with well-chosen truncation are manageable; overly short indexes
  (1–2 bytes) cause excessive "blank decryptions."

---

## 7. API Design Considerations

### Core Primitives Needed

```
BlindIndexKey        — Distinct from VaultKey, implements Zeroize + ZeroizeOnDrop
BlindIndexConfig     — Truncation length, hash strategy (fast vs. slow), transforms
BlindIndex::compute  — Deterministic keyed hash → truncated IndexValue
CompoundBlindIndex   — Combine multiple fields before hashing
Transform functions  — Normalize input (lowercase, first N chars, etc.)
IndexPlanner         — Calculate safe truncation lengths given population/cardinality
```

### Integration Points

- **`storage.rs`** — Helpers for adding index columns, querying by index, filtering
  false positives after decryption.
- **`crdt.rs`** — If CRDT documents need local search, blind indexes on document fields.
- **Tauri plugin** — New commands: `create_blind_index`, `query_by_blind_index`.
- **`error.rs`** — New `BlindIndexError` variant following the opaque error pattern.

### What NOT to Expose

- No server-side search API (preserves zero-knowledge guarantee)
- No `LIKE`/prefix/range queries (blind indexes only support equality)
- No automatic/implicit index creation — explicit opt-in per field required

---

## 8. How Existing Libraries Approach This

### CipherSweet (Paragonie)
- PHP/Node.js. Field-level encryption (XSalsa20-Poly1305) with separate blind indexes.
- Per-field, per-index derived keys. Supports transforms and compound indexes.
- Includes a planner tool for safe truncation length calculation.
- Two backends: FIPSCrypto (PBKDF2-SHA384) and ModernCrypto (BLAKE2b/Argon2id).

### AWS Database Encryption SDK
- DynamoDB-focused. Uses "beacons" (truncated HMAC tags).
- Standard beacons (single-field) and compound beacons (multi-field).
- Multi-tenant support with per-tenant HMAC keys.
- New databases only — no retroactive indexing.

### HashiCorp Vault Transit Engine
- Convergent (deterministic) encryption rather than separate blind indexes.
- Simpler but weaker: the ciphertext itself is deterministic, not just a side index.

### Acra (Cossack Labs)
- Database proxy. HMAC-SHA256 blind indexes alongside AcraStruct encrypted data.
- Transparently rewrites SQL WHERE clauses.
- Enterprise Edition adds prefix search via multiple prefix hashes.

---

## 9. Recommendations

1. **Scope to local-only** — Blind indexes in SQLCipher only, never synced to any
   server. This preserves the zero-knowledge guarantee for the relay/server layer.

2. **Separate key hierarchy** — Blind index keys derived from the vault root (same
   BIP39 mnemonic) but with a distinct BLAKE3 context string, ensuring they are
   cryptographically independent from encryption keys.

3. **Two hash strategies** — Fast (BLAKE3-keyed) for high-cardinality fields (email,
   UUID), slow (Argon2id with reduced parameters) for low-cardinality fields (status,
   boolean, country code).

4. **Mandatory truncation with a planner** — No full-length index output allowed. A
   built-in planner calculates safe bit-lengths given population size and input domain
   cardinality, following CipherSweet's coincidence count formula.

5. **Compound indexes** — Support combining multiple fields into a single index to
   mitigate frequency analysis on individual low-cardinality fields.

6. **Explicit opt-in** — No implicit indexing. Developers must choose which fields to
   index and configure truncation, acknowledging the privacy trade-off via the API
   design (builder pattern with required safety parameters).

7. **Design for key rotation from day one** — Versioned index keys, dual-read support
   during migration, background re-indexing capability.

8. **Update SECURITY.md** — Document the leakage model, known attack vectors (frequency
   analysis, chosen-plaintext, cross-correlation), and safe usage patterns.

9. **Constant-time index comparison** — Use `subtle::ConstantTimeEq` for all index
   value comparisons to prevent timing side channels, consistent with existing SDK
   patterns.

10. **Zeroize all intermediate values** — Hash inputs, pre-truncation outputs, and key
    material must be zeroized after use, following the SDK's established zeroization
    discipline.

---

## 10. Risk Matrix

| Risk                        | Likelihood | Impact | Mitigation                              |
|-----------------------------|------------|--------|-----------------------------------------|
| Frequency analysis          | High       | Medium | Truncation, compound indexes, planner   |
| Chosen-plaintext attack     | Medium     | High   | Rate limiting, audit logging            |
| Cross-index correlation     | Medium     | Medium | Compound indexes, documentation         |
| Blind index key compromise  | Low        | High   | Slow hashing, key rotation support      |
| Scope creep to server-side  | Medium     | Critical | API design enforces local-only scope  |
| Mobile performance impact   | Medium     | Medium | Tunable Argon2id params, benchmarking   |
| Key rotation operational cost | High     | Medium | Version from day one, migration tooling |

---

## References

- [CipherSweet Blind Indexing Internals](https://ciphersweet.paragonie.com/internals/blind-index)
- [CipherSweet Security Properties](https://ciphersweet.paragonie.com/security)
- [CipherSweet Blind Index Planning](https://ciphersweet.paragonie.com/php/blind-index-planning)
- [AWS Database Encryption SDK — Searchable Encryption](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html)
- [AWS Database Encryption SDK — Beacons](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/beacons.html)
- [IronCore Labs — Encrypted Search](https://ironcorelabs.com/docs/data-control-platform/concepts/encrypted-search/)
- [Cossack Labs Acra — Searchable Encryption](https://docs.cossacklabs.com/acra/security-controls/searchable-encryption/)
- [ankane/blind_index (Ruby)](https://github.com/ankane/blind_index)
- [BlindexTEE: Blind Index Approach for TEE-supported E2EE DBMS](https://arxiv.org/html/2411.02084v1)
