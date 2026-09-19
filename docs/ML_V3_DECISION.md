# NetShield ML v3 Decision Record

## Purpose

NetShield uses machine learning to classify WiFi traffic windows as normal or malicious. The v3 ML pipeline converts live or AWID3-derived WiFi packets into 5-second feature windows, extracts the 31-feature v3 schema, and applies a Random Forest model for binary Normal / Attack classification.

The model is evaluated as part of the intrusion detection pipeline. Rule-style packet thresholds are not the final attack decision mechanism.

## Production Model

Current production v3 model:

```text
backend/ml/models/random_forest_awid3_v3_expanded.joblib
```

This model remains the current production model.

## Dataset

The v3 expanded AWID3 dataset used for the current production model investigation is:

```text
D:\New folder\Desktop\NetShield_AWID3_ML_v3_expanded\train.csv
D:\New folder\Desktop\NetShield_AWID3_ML_v3_expanded\test.csv
```

The feature schema is the existing 31-feature v3 schema from `backend/ml/v3_feature_schema.py`.

## Current v3 Test Performance

On the unchanged v3 expanded test set:

- Accuracy: 93.75%
- Attack precision: 100%
- Attack recall: 93.75%
- Attack F1: 96.7742%
- Test attack windows: 16
- Correctly detected attack windows: 15
- Missed attack windows: 1

The production model missed one attack window.

## False-Negative Investigation

The missed attack was:

- Test row: 3
- Actual label: Attack
- Predicted label: Normal
- Attack probability: 0.12
- Source capture: `2.Disas\Disas_40.csv`
- Window index: 1

This window was a low-volume, disassociation-heavy attack window. Its key pattern included low packet volume with meaningful disassociation activity:

- `total_packets = 498`
- `packets_per_second = 99.6`
- `disassociation_count = 82`
- `disassociation_per_second = 16.4`
- `max_disassoc_1s = 82`
- `disassoc_burst_ratio = 0.164659`

The investigation showed that this pattern is sparsely represented in the training data. Similar Disas attack behavior exists, but row 3 remains unusual compared with most training attack windows.

## Investigation Performed

The v3 false-negative investigation included:

- Feature-level analysis
- Random Forest decision-path analysis
- Training representation analysis
- Source-capture provenance analysis
- Disas candidate analysis
- Window coverage analysis
- Controlled v3.1 Random Forest experiments

The decision-path analysis showed that row 3 often followed tree paths containing low-volume traffic features before disassociation-specific features were reached. This is path-frequency evidence only, not causal feature importance.

## Controlled v3.1 Experiment

A controlled v3.1 Random Forest experiment was run using the same training and test CSVs, the same 31-feature schema, and separate experimental model filenames.

Configurations tested:

- Baseline retrain
- `min_samples_leaf = 2`
- `min_samples_leaf = 3`
- `min_samples_leaf = 5`
- `min_samples_leaf = 2` with 500 trees

All configurations produced the same test-set classification metrics:

- Accuracy: 93.75%
- Attack precision: 100%
- Attack recall: 93.75%
- Attack F1: 96.7742%
- One missed attack
- Row 3 remained classified as Normal

The leaf-size variants increased the attack probability for row 3, but never enough to change the final classification.

## Production vs Experimental Models

Production/current model:

```text
backend/ml/models/random_forest_awid3_v3_expanded.joblib
```

Experimental v3.1 models were saved separately using filenames beginning with:

```text
backend/ml/models/random_forest_awid3_v3_1_
```

The v3.1 files are experimental artifacts only. They do not replace the production/current v3 model.

## Final Decision

The existing v3 production model remains unchanged.

Decision:

- Keep the existing v3 production model.
- Do not replace it with a v3.1 variant.
- Do not tune specifically for row 3.
- Do not duplicate or oversample the single unusual window merely to force a classification change.
- Treat the missed row 3 result as a documented limitation of the current training representation.

## Engineering Principle

The model should be evaluated on overall generalization and representative test performance, not optimized around one unusual false-negative test window.

Improving one difficult row is not sufficient justification for replacing the production model unless the change also improves or preserves broader model behavior on representative evaluation data.
