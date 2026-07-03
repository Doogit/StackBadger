# reports/data — vendored ASVS crosswalk data

Static reference data for the ASVS-4.0 coverage crosswalk (`reports/crosswalk.py`).
These files are committed verbatim from OWASP so a CASA/Tier-2 scan that still grades
against ASVS 4.0.3 can be projected from the 5.0-authored probe tags without a live
network fetch.

## Provenance

| File | Source | Retrieved |
| --- | --- | --- |
| `mapping_v5.0.0_to_v4.0.3.yml` | [OWASP/ASVS `5.0/mappings/mapping_v5.0.0_to_v4.0.3.yml` @ `v5.0.0`](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/mappings/mapping_v5.0.0_to_v4.0.3.yml) | 2026-07-03 |
| `mapping_v4.0.3_to_v5.0.0.yml` | [OWASP/ASVS `5.0/mappings/mapping_v4.0.3_to_v5.0.0.yml` @ `v5.0.0`](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/mappings/mapping_v4.0.3_to_v5.0.0.yml) | 2026-07-03 |

Both files are unmodified OWASP artifacts. The OWASP Application Security Verification
Standard is published under **CC BY-SA 4.0** (Creative Commons Attribution-ShareAlike);
attribution: The OWASP Foundation, ASVS project. See <https://github.com/OWASP/ASVS>.

- `mapping_v5.0.0_to_v4.0.3.yml` — **forward** map keyed by 5.0 requirement, listing the
  4.0.3 requirement(s) each 5.0 control descends from (`MOVED FROM` / `MERGED FROM` /
  `SPLIT FROM` / `COVERS` / `DEPRECATES`). Drives the 5.0 -> 4.0 projection.
- `mapping_v4.0.3_to_v5.0.0.yml` — **reverse** map keyed by 4.0.3 requirement. Its
  `DELETED, <REASON>` annotations are the authoritative source for the dropped supplement
  below; it is not read at runtime, only vendored as the derivation source.

## Derived file

`asvs-4.0-dropped.yaml` — the "43-dropped supplement": the 4.0.3 requirements that have
**no** 5.0 successor and are therefore not covered by any 5.0-authored probe. Derived
verbatim from `mapping_v4.0.3_to_v5.0.0.yml` — every 4.0.3 entry whose `tag-v5.0.0` is a
terminal `DELETED, <REASON>` with `<REASON>` in {`NOT IN SCOPE`, `INSUFFICIENT IMPACT`,
`INCORRECT`}. Entries that are `DELETED` but `MERGED`/`COVERED`/`DEPRECATED` into a 5.0
successor are *not* dropped and are excluded. Total 43: 27 not in scope, 11 insufficient
impact, 5 incorrect. Regenerate (do not hand-edit) by filtering the reverse mapping on
those three terminal reasons.

The reverse map additionally carries 7 terminal `DELETED, NOT PRACTICAL` requirements
(`8.3.6`, `10.2.1`–`10.2.6`) that also have no 5.0 successor. They are deliberately
**excluded** to match the plan's canonical 43 (OWASP marked them not practical to
verify); a test pins this omission so a regeneration cannot re-introduce them silently.
Include them (with a `not practical` reason) only if a CASA assessor requires the full
50-requirement no-successor set.
