# Release validation

Checked on 29 October 2026 in an isolated publishing copy.

- Notebook schema and transformed Python syntax validated across all 39 code cells.
- The portable guardrail module passed the original authored status-and-rule regression cases; tests also require an empty post-filter rule list.
- Standard-library CLI demonstration exercised without a GPU, model download or provider request.
- Source scanned for credentials; private Drive backups, saved outputs and widget metadata excluded.

The standalone policy default for maximum answer length is 1,200 characters. A full notebook run derives its own threshold from training data; set TRUSTDESK_MAX_ANSWER_CHARS to that value when reproducing its exact policy contract.

Not performed: fresh LoRA training, pretrained/adapted generation comparison, full protected evaluation, or independent human safety review. Finite authored fixtures do not establish universal safety or factual correctness. Source-only notebook outputs were cleared rather than presented as newly generated results.
