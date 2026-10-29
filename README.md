# TrustDesk AI

A customer-support AI research project combining reproducible data cleaning, LoRA adaptation of Qwen2.5-0.5B-Instruct and deterministic PASS / REVISE / BLOCK response guardrails.

## Try the portable guardrail demo

Python 3.12 or 3.13 is recommended. No API key, GPU or third-party package is needed for the policy demo.

```bash
python demo.py
python demo.py --answer "Send me your password here."
python -m unittest discover -s tests -v
```

This evaluates a supplied draft. It does not pretend to generate a model response or perform account operations. The standalone policy module was extracted from the project notebook. Its default maximum answer length is 1,200 characters; set `TRUSTDESK_MAX_ANSWER_CHARS` to the value computed by your notebook run when reproducing that run's contract.

## Full model workflow

Open [the notebook](notebooks/trustdesk-ai.ipynb) in a fresh Google Colab T4 runtime. It downloads a pinned Hugging Face dataset revision, profiles and cleans records, makes leakage-aware splits, trains a response-only LoRA adapter, compares saved model outputs and applies the policy layer. The pinned dataset and base-model revisions are recorded in its configuration.

The source-only portfolio notebook has cleared outputs and private widget/account metadata. Full training requires internet, the documented model/data access and GPU compute; it is not performed by the CPU regression suite. Dataset records, private Drive recovery archives and trained adapters are not bundled. Optional Drive backup remains a notebook feature and requires the user's explicit connection there.

## Evaluation boundaries

The included regression suite reuses the notebook's authored status/rule cases. Passing finite fixtures does not establish universal natural-language safety, factual accuracy or correct intent routing. Historical experiments must be distinguished from a new notebook run. See [validation](docs/VALIDATION.md).

Author: Vishnu Bhaiya. Developed for advanced-AI coursework using Qwen, Hugging Face Transformers and PEFT. Dataset and upstream model terms remain applicable.
