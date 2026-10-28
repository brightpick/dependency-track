# Durable component license curation

| Status   | Date       | Author(s)                                          |
|:---------|:-----------|:---------------------------------------------------|
| Accepted | 2026-07-22 | [@canikrichard](https://github.com/canikrichard)   |

## Context

License policy violations frequently point at a *data* problem rather than a
*risk* problem: the component's license is known, but the uploaded BOM either
omits it or declares it incorrectly. The existing remediation options are all
unsatisfactory:

* Suppressing the violation hides a finding instead of correcting the data,
  and the suppression does not explain what the license actually is.
* Editing the component through the REST API does not survive the next BOM
  upload: `ImportBomActivity` synchronizes all component fields from the BOM
  on every import (intended behavior), so manual corrections are silently
  overwritten. Component rows are also deleted and recreated as components
  enter and leave the BOM, so nothing keyed to the component row survives.
* Feature request [#251] (open since 2018) confirms there is no upstream
  mechanism for durable license overrides, and no extension point hooks into
  BOM ingestion or policy evaluation.

At the same time, allowing arbitrary component edits alongside BOM-managed
data creates a second, uncontrolled write path: edits bypass any audit trail
and produce component data whose provenance is unclear.

## Decision

License curation becomes a first-class, durable, audited concept, and ad-hoc
component mutation is removed:

1. **Component analyses** (`COMPONENT_ANALYSIS`, `COMPONENT_ANALYSIS_COMMENT`)
   store a per-component license override and free-text details, keyed by the
   component's *identity* (purl, falling back to group/name/version) within a
   project — never by the component row's primary key, because rows are
   recreated across uploads. Every field change appends an audit comment
   recording the old and new value and the author. The declared license is
   snapshotted on first override so clearing the override restores the
   BOM-declared value. Overrides are re-applied at the end of every BOM
   import, after field synchronization and before policy evaluation, so
   LICENSE violations always evaluate against the curated license.

2. **Component policies** (`COMPONENT_POLICY`) automate the same mechanism: a
   CEL condition over component and project fields, evaluated at every BOM
   import with first-match-wins priority ordering, maintains component
   analyses carrying the policy's license and details. Manual analyses always
   win over policy-maintained ones. When no policy matches anymore, the
   policy-maintained analysis is retracted and the imported license applies
   again. Policy actions write the same audit comments as manual edits, with
   the policy identified as the author.

3. **Imported components are read-only.** Component update, delete, and
   property mutations respond `405` for components that originate from BOM
   uploads; the BOM is their single source of truth and curation happens via
   analyses and policies. Components created by hand through the REST API
   carry a `MANUALLY_CREATED` flag: they remain fully editable and are never
   deleted by BOM synchronization. If a BOM component matches a manual
   component's identity, the BOM takes ownership — the flag clears and the
   component becomes read-only.

## Consequences

* License corrections survive BOM re-uploads, carry a complete audit trail,
  and can be automated fleet-wide with policies, satisfying traceability
  expectations without blocking uploads.
* Policy evaluation sees curated licenses, so a corrected license resolves
  the violation instead of requiring a suppression.
* The BOM remains the single source of truth for imported component data;
  the only durable divergence is the explicit, audited license override.
* Manually created components support inventory that has no SBOM producer,
  at the cost of a dual regime (editable vs. read-only) that the UI must
  communicate clearly.
* `ImportBomActivity` gains one hook at the end of component processing;
  this is deliberately the only touch point in the ingestion path to keep
  rebases onto upstream releases cheap.
* Existing API consumers that relied on mutating imported components will
  receive `405` and must migrate to component analyses.

## Follow-up (2026-10-23)

Later work adds four details to the decision. None of them changes it.

A multi-license is curated as a whole. An override fills one of three license slots that mirror
the component: a resolved license (`LICENSE_ID`), an SPDX expression of known licenses
(`LICENSE_EXPRESSION`), or a free-text name (`LICENSE_NAME`). At most one slot is set, and a
check constraint on `COMPONENT_ANALYSIS` and `COMPONENT_POLICY` enforces it. Reducing a
multi-license to one of its members would record a decision nobody made.

Policies can see that a license is curated. `COMPONENT.LICENSE_CURATED` marks a component whose
license an analysis set, and policy conditions read it as `component.license_curated`. Every
import resets the flag while it synchronizes the component fields, and the analysis applier sets
it again, so a deleted or retracted analysis leaves no flag behind. This adds a second touch point
in `ImportBomActivity`, next to the applier hook. Component policies run before the applier and
always see the flag as false.

Curation is its own permission. `COMPONENT_ANALYSIS` covers analyses, their comments and the
component policies; analyses required `POLICY_MANAGEMENT` before. The migration grants it to the
Administrators team, and other teams get it by hand. A component policy acts across the whole
portfolio, so a team with this permission can change licenses in projects it cannot otherwise
access.

Clearing an override or deleting an analysis writes the declared-license snapshot back at once,
not on the next upload. It does so only on the components that carry the override, so a
component that a later upload changed keeps that upload's license.

[#251]: https://github.com/DependencyTrack/dependency-track/issues/251
