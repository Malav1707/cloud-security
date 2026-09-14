# ☁️ Cloud Security — Real-Time Anomaly Detection + GenAI Breach Minimisation

## Introduction

This project is an end-to-end pipeline (built as a single Jupyter/Colab notebook, `cloud_security_final.ipynb`) that detects anomalous cloud-security events in a dataset and automatically generates an incident-response playbook for the ones that matter most.

It combines two layers:

1. **An unsupervised machine learning layer** — an Isolation Forest model (compared across four hyperparameter configurations) that scores every event in a cloud-security dataset for how anomalous it looks, based on severity, threat category, mitigation effectiveness, and incident volume.
2. **A GenAI reasoning layer** — a Retrieval-Augmented Generation (RAG) pipeline that takes the highest-risk anomalies the model flags, retrieves relevant MITRE ATT&CK and cloud-threat knowledge, and asks Claude to produce a structured remediation playbook: confirmed attack type, root cause, immediate containment steps, long-term hardening steps, blast-radius estimate, and SOC (Security Operations Center) priority.

The result is a notebook that goes from "raw CSV of security events" to "which of these are real threats, and what should the SOC do about each one right now" — with EDA, model comparison/evaluation, a real-time scoring function, a risk-triage system, and an interactive `ipywidgets` dashboard along the way.

---

## What it does, end to end

| Step | What happens |
|---|---|
| 1. Install & Import | Installs `anthropic`, `scikit-learn`, `pandas`, `numpy`, `matplotlib`, `seaborn`, `joblib`, `ipywidgets` and sets global plotting/reproducibility config |
| 2. Dataset Upload & Auto-Detection | Loads `cloud_security_dataset.csv` (prompts for upload in Colab) with automatic encoding/separator detection, and auto-identifies the label, numeric, categorical, timestamp, and mitigation columns |
| 3. EDA & Visualisation | Prints dataset shape/summary stats and renders a multi-panel EDA dashboard (threat category distribution, severity breakdown, etc.) |
| 4. Feature Engineering | Builds the anomaly ground-truth label from domain rules, encodes categorical fields, and derives engineered features (risk score, incidents-per-case, recency, low-mitigation/high-incident flags), then standardizes everything |
| 5. Isolation Forest — 4 configs | Trains four Isolation Forest variants (Baseline, High-Tree, Tuned, Robust) with different `n_estimators`, `max_samples`, `contamination`, and `max_features` |
| 6. Full Evaluation | Compares all four configs on Precision, Recall, F1, AUC-ROC, and training time; plots bar charts, confusion matrices, ROC curves, a PCA 2D projection of the best model's decisions, and feature-importance-by-correlation |
| 7. Real-Time Scoring | A reusable `score_event()` function that takes a single new event (as a dict) and returns an anomaly flag, a continuous anomaly score, and a severity band, without retraining |
| 8. Risk Triage | Buckets every flagged anomaly into `CRITICAL` / `HIGH` / `MEDIUM` using percentile thresholds (90th / 67th) of the anomaly score distribution, and visualizes the breakdown |
| 9. GenAI RAG Remediation | For the top CRITICAL + HIGH events, retrieves a matching entry from a hand-curated MITRE ATT&CK knowledge base and sends a structured prompt to Claude, which returns a JSON remediation playbook per event |
| 10. Interactive Dashboard | An `ipywidgets` form where you can manually enter a hypothetical event's attributes and get an instant Isolation Forest verdict + (optionally) a live GenAI playbook |
| 11. Save Artefacts | Persists the trained model, scaler, encoders, thresholds, flagged-anomaly CSV, remediation-playbook CSV, comparison table, and every chart to disk (and offers a download in Colab) |

---

## Dataset & ground-truth labeling

The notebook is designed to work with **any** cloud-security CSV via `smart_load()` (tries multiple encodings/separators) and `auto_detect_columns()` (keyword-matches column names for label/numeric/categorical/timestamp/mitigation fields). The dataset it was built and tuned against has these fields per event: `Year`, `Threat_Category`, `Layer` (IaaS/PaaS/SaaS), `Severity` (Low/Medium/High), `Incident_Count`, `Mitigation_Effectiveness` (0–10), `Reported_Cases`.

Because the dataset has no pre-existing "is this an anomaly" label, one is constructed from domain-knowledge rules (`build_anomaly_label`):

- **Rule 1:** `Severity == High` and `Mitigation_Effectiveness < 5` → anomaly.
- **Rule 2:** Threat is in a "high-risk" set (`DDoS Attack`, `Data Breach`, `Zero-Day Vulnerability`, `Container Escape`, `Supply Chain Compromise`) **and** `Severity == Medium` **and** `Mitigation_Effectiveness < 3.5` → anomaly.
- **Rule 3:** `Incident_Count > 75` **and** `Mitigation_Effectiveness < 4` → anomaly, regardless of category.
- Otherwise → normal.

This label is only used to **evaluate** the unsupervised model (Precision/Recall/F1/AUC) and to set the contamination parameter — the Isolation Forest itself is trained unsupervised, without seeing this label.

---

## Feature engineering

| Feature | Meaning |
|---|---|
| `year_recency` | `Year - min(Year)` — how recent the event is relative to the dataset |
| `Threat_enc` | Label-encoded `Threat_Category` |
| `Layer_enc` | Label-encoded `Layer` |
| `Severity_enc` | Ordinal-encoded `Severity` (Low=0, Medium=1, High=2) — preserves order, unlike one-hot |
| `Incident_Count`, `Mitigation_Effectiveness`, `Reported_Cases` | Raw numeric fields |
| `risk_score` | `Severity_enc * (10 - Mitigation_Effectiveness)` — a composite "how bad, times how unmitigated" score |
| `incident_per_case` | `Incident_Count / (Reported_Cases + 1)` — incident density per reported case |
| `low_mitigation_flag` | 1 if `Mitigation_Effectiveness < 4` |
| `high_incident_flag` | 1 if `Incident_Count > 70` |

All 11 features are standardized with `StandardScaler` before being fed to the model — Isolation Forest doesn't strictly require scaling (it's tree-based), but scaling keeps the engineered composite features (`risk_score`, `incident_per_case`) on a comparable footing for the correlation/feature-importance analysis later in the notebook.

---

## Model: Isolation Forest

**Why Isolation Forest and not a supervised classifier?** In a real SOC setting, you rarely have clean, exhaustive labels for "this was an attack." Isolation Forest is unsupervised — it isolates outliers by recursively partitioning the feature space, on the intuition that anomalies are "few and different" and therefore take fewer random splits to isolate than normal points. That matches the anomaly-detection framing this project needs, and it doesn't require the constructed label to train (only to evaluate).

### Four configurations compared

| Config | `n_estimators` | `max_samples` | `contamination` | `max_features` | Intent |
|---|---|---|---|---|---|
| Baseline | 100 | `'auto'` | true anomaly rate | 1.0 | sklearn defaults, contamination set to the actual anomaly rate in the data |
| High-Tree | 300 | 512 | true anomaly rate | 1.0 | More trees → lower variance / more stable anomaly scores |
| Tuned | 200 | 0.8 | true rate − 0.02 | 0.8 | Sub-sampled features per tree → more diversity between trees |
| Robust | 300 | 1.0 | true rate + 0.02 | 0.6 | Full sample, higher contamination → biased toward higher recall |

Each is trained, scored, and evaluated against the domain-rule label; the winner is selected by **highest F1** (`BEST_CONFIG = max(results, key=lambda k: results[k]['F1'])`), balancing precision and recall rather than optimizing either alone.

### Evaluation artifacts produced
- Comparison table (Precision / Recall / F1 / AUC-ROC / training time) for all four configs.
- Grouped bar charts per metric.
- Confusion matrices for all four configs side by side.
- ROC curves with AUC in the legend.
- A 2D PCA projection of the feature space, colored by ground truth vs. by the best model's predictions, for a visual sanity check of separability.
- Feature-importance-by-correlation: absolute Pearson correlation of each feature with the best model's anomaly score.

---

## Real-time scoring engine

`score_event(event_dict)` lets you score a **single new event** without retraining:
1. `encode_new_event()` fills in sensible defaults for any missing fields, applies the same label encoders/ordinal mapping/derived-feature formulas used at training time, and scales with the fitted `scaler`.
2. The trained `best_model` predicts (`+1`/`-1`) and produces a continuous anomaly score via `-model.decision_function(...)` (negated so higher = more anomalous, which is more intuitive to read).
3. If flagged as an anomaly, the score is compared against the 67th/90th percentile thresholds (computed from the training-set anomaly-score distribution) to assign a `MEDIUM` / `HIGH` / `CRITICAL` severity band.

This is the function both the "test events" demo and the interactive dashboard call under the hood — it's the same code path in both places, so what you see in the dashboard is exactly what the pipeline would do on a genuinely new, unseen event.

---

## Risk triage (severity banding)

Every event the model flags as an anomaly is bucketed by its anomaly score:

- **CRITICAL** — score ≥ 90th percentile of flagged anomalies' scores
- **HIGH** — score ≥ 67th percentile
- **MEDIUM** — everything else that's still flagged

This turns a binary "anomaly / not anomaly" output into a prioritized queue a SOC analyst could actually work through, and it's what determines which events get escalated to the GenAI remediation step (all CRITICAL events, plus the top few HIGH events, to keep API usage bounded).

---

## GenAI RAG breach-minimisation (Claude)

### Architecture

```
Isolation Forest flags anomaly
        │
        ▼
Context Builder
  ├── Event features (real data)
  ├── MITRE ATT&CK knowledge base (RAG retrieval)
  └── Cloud threat playbooks (RAG retrieval)
        │  structured prompt
        ▼
   Claude (claude-sonnet-4-20250514)
  ├── Validate / correct attack classification
  ├── Root cause analysis
  ├── Immediate containment (3 actions)
  ├── Long-term hardening (3 actions)
  ├── Blast radius estimate
  └── SOC priority (P1 / P2 / P3)
        │
        ▼
 Structured JSON Playbook → Dashboard
```

### GenAI techniques used

| Technique | How it's used here |
|---|---|
| **RAG** | A hand-curated knowledge base (`THREAT_KB`) covering all 10 threat categories — MITRE tactic, MITRE technique, known risk factors, immediate actions, and hardening steps — is retrieved by threat type and injected into the prompt per event |
| **Structured output** | The prompt embeds an exact JSON schema and instructs the model to return *only* JSON, no prose or markdown fences |
| **Chain-of-thought** | The prompt explicitly asks Claude to validate or correct the ML model's attack classification before producing remediation steps, rather than accepting the label at face value |
| **Domain grounding** | Every prompt includes the MITRE ATT&CK Cloud Matrix tactic/technique for that threat category, so responses map to a recognized security framework rather than generic advice |
| **Contextual reasoning** | All seven raw event fields (not just severity) are passed in, so the response can reason about e.g. mitigation effectiveness as evidence of "attacker still has a foothold" |

### Knowledge base coverage

`THREAT_KB` has one entry per threat category, each with `mitre_tactic`, `mitre_technique`, `risk_factors`, three `immediate` actions, and three `hardening` actions:

DDoS Attack · Data Breach · Zero-Day Vulnerability · API Exploit · Insider Threat · IAM Misconfiguration · Container Escape · Encryption Failure · Supply Chain Compromise · Compliance Violation

### Response schema

```json
{
  "confirmed_attack_type":  string,
  "confidence":             "LOW|MEDIUM|HIGH",
  "root_cause_summary":     string (max 50 words),
  "mitre_tactic":           string,
  "mitre_technique":        string,
  "immediate_actions":      [string, string, string],
  "long_term_hardening":    [string, string, string],
  "estimated_blast_radius": "LOW|MEDIUM|HIGH|CRITICAL",
  "soc_priority":           "P1|P2|P3",
  "monitoring_kpis":        [string, string]
}
```

### Live API vs. mock mode

The notebook reads `ANTHROPIC_API_KEY` from Colab Secrets (or an environment variable as a fallback). If a valid-looking key (`sk-...`) is present, it calls the live Claude API (`claude-sonnet-4-20250514`) and parses the JSON response (stripping markdown code fences defensively, in case the model wraps its output). **If no key is present, or the API call throws, it falls back to `mock_claude_response()`** — a deterministic, rule-based response generator that pulls from the same `THREAT_KB` so the entire pipeline (including the dashboard) still runs end-to-end without any API cost or network dependency. This makes the notebook fully runnable and demonstrable even without Anthropic API access.

---

## Interactive dashboard

Built with `ipywidgets`. Lets you set `Threat_Category`, `Layer`, `Severity`, `Year`, `Incident_Count`, `Mitigation_Effectiveness`, and `Reported_Cases` via dropdowns/sliders, then click **Analyse Event** to:
1. Run the event through `score_event()` and display the Isolation Forest verdict (anomaly / normal, score, severity band).
2. If flagged as an anomaly and "Generate AI Playbook" is checked, run it through `run_genai_remediation()` and render the full playbook (confirmed type, confidence, SOC priority, blast radius, MITRE technique, root cause, immediate actions, hardening steps, monitoring KPIs) as styled HTML in the output cell.

This is the fastest way to demo the whole pipeline on a single, arbitrary hypothetical event without touching the dataset.

---

## Artefacts saved

| File | Contents |
|---|---|
| `best_if_model.pkl` | The winning Isolation Forest model (joblib) |
| `scaler.pkl` | The fitted `StandardScaler` |
| `pipeline_meta.pkl` | Label encoders, feature column order, year baseline, and the p67/p90 severity thresholds — everything needed to reproduce `score_event()` outside the notebook |
| `anomaly_events.csv` | All events flagged as anomalies, with score + severity band |
| `remediation_playbook.csv` | Summary table of the GenAI remediation output for the top events |
| `if_comparison.csv` | The four-config hyperparameter comparison table |
| `eda_dashboard.png`, `feature_correlation.png`, `if_comparison.png`, `confusion_matrices.png`, `roc_curves.png`, `pca_scatter.png`, `feature_importance.png`, `risk_triage.png`, `genai_analysis.png` | All charts generated throughout the notebook |

In Colab, the three most portable artefacts (`remediation_playbook.csv`, `if_comparison.csv`, `best_if_model.pkl`) are also offered as direct downloads.

---

## Tech stack

- **Data/ML:** `pandas`, `numpy`, `scikit-learn` (`IsolationForest`, `StandardScaler`, `LabelEncoder`, `PCA`, metrics)
- **Visualization:** `matplotlib`, `seaborn`
- **GenAI:** `anthropic` Python SDK, Claude `claude-sonnet-4-20250514`
- **UI:** `ipywidgets` (Colab/Jupyter interactive dashboard)
- **Persistence:** `joblib`

---

## How to run

1. Open `cloud_security_final.ipynb` in Google Colab (recommended) or Jupyter.
2. Upload `cloud_security_dataset.csv` — in Colab, the 📁 Files panel; locally, place it in the same directory as the notebook.
3. **Optional but recommended:** add your Anthropic API key as a Colab Secret named `ANTHROPIC_API_KEY` (🔑 Secrets panel) to get live Claude-generated remediation playbooks instead of the deterministic mock responses.
4. Run all cells top to bottom (`Runtime → Run all` in Colab). The first cell installs all required packages, so no manual `pip install` is needed.
5. Use the interactive dashboard at the bottom to test arbitrary events on demand.

**Note on API keys:** never commit a real `ANTHROPIC_API_KEY` into the notebook or a public repo. The notebook is written to read it from Colab Secrets or an environment variable specifically so the key never has to be hardcoded into a cell.

---

## Design notes / things worth knowing about the approach

- **Unsupervised-first, label-second:** the anomaly label is a rule-based approximation of ground truth used purely for evaluation and setting `contamination`; the model itself never sees it during fitting. This mirrors how anomaly detection is used in practice, where labeled attack data is scarce.
- **Contamination is estimated, not guessed:** `TRUE_CONTAMINATION` is computed directly from the constructed label's positive rate, so the "Baseline" and "High-Tree" configs aren't relying on sklearn's generic default — they're told the actual expected anomaly rate in this specific dataset.
- **Selection by F1, not accuracy:** with a naturally imbalanced anomaly rate, accuracy would be a misleading metric (a model that predicts "normal" for everything could score deceptively well). F1 balances precision and recall, which is what a SOC actually cares about — too many false positives burns analyst time; too many false negatives misses real breaches.
- **Percentile-based severity bands over fixed thresholds:** using the 67th/90th percentile of the *flagged* anomalies' own score distribution (rather than a hardcoded score cutoff) makes the CRITICAL/HIGH/MEDIUM banding adapt automatically to whatever score range a given dataset or model produces.
- **RAG grounding reduces hallucination risk:** rather than asking Claude to freely generate MITRE mappings and remediation steps from parametric knowledge alone, the prompt retrieves and injects a fixed, human-curated KB entry per threat category — the model's job is to reason over that grounded context (and the real event data) rather than invent facts.
- **Graceful degradation everywhere:** dataset loading tries multiple encodings/separators; column detection falls back sensibly if keywords don't match; the GenAI step falls back to a deterministic mock if there's no API key or the call fails. The notebook is built to run to completion in a fresh environment with zero manual debugging.
