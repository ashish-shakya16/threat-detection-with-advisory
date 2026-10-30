# Source Mapping and Verification Record

## Uploaded sources analyzed

| Ref. | Source | Main topic and evidence used | Evaluation / limitation |
|---|---|---|---|
| [1] | Kaufhold et al., 2022 | CERT threat observatory; dashboard and operational requirements | 12 expert walkthrough/interviews; not an accuracy benchmark |
| [2] | Manoharan and Sarker, 2022 | AI/ML, anomaly detection, NLP, future directions | Broad review; limited reproducible experimental detail |
| [3] | Abeywardena et al., 2023 | Automated SOC threat-advisory generation | Proposed dashboard; detailed validation limited |
| [4] | Ismail, 2024 | AI/NLP threat detection, phishing, behavior, response | Review and interviews; no reproducible benchmark |
| [5] | Rajendran et al., 2024 | CNN/RNN deep learning and anomaly detection | Reports CNN 93% and RNN 96%; dataset/setup details require verification |
| [6] | Kumar and Bhat, 2025 | Text mining, CVSS, classifiers, autoencoder novelty detection | Reports XGBoost accuracy 92%, precision 0.91, recall 0.94, AUC 0.95; scope/drift limited |
| [7] | Balaji et al., 2025 | GCN, LSH, LIME, LLM contextual analysis | File-upload setting; external robustness evidence limited |
| [8] | Schmitt and Koutroumpis, 2025 | AI security and targeted policy measures | Conceptual analysis, not a detection experiment |
| [9] | Liu et al., 2025 | CyLens and agentic LLM cyber-threat intelligence | 271,570 threat reports and comparative evaluation claimed; safety/generalization open |
| [10] | Zhivonitko, 2026 | Domain-tuned conversational cyber-threat advisor | LoRA-tuned open models; thesis-scale evaluation |
| [11] | Kumar and Bhat, 2026 | Temporal threat-intelligence prediction | Reports 7--10% improvement over non-temporal baselines |

## External source verification

The following external references were checked against official publisher, proceedings, or DOI pages before inclusion: Sommer and Paxson [12], Buczak and Guven [13], Shone et al. [14], Mirsky et al. [15], Moustafa and Slay [16], Tavallaee et al. [17], Liao et al. [18], Ribeiro et al. [19], Biggio and Roli [20], Lewis et al. [21], and Arp et al. [22]. Their DOI or official publication links are included in the LaTeX bibliography where available.

| Ref. | Verified venue | DOI / official source | Role |
|---|---|---|---|
| [12] | IEEE Symposium on Security and Privacy, 2010 | `10.1109/SP.2010.25` | Closed-world and generalization limitations |
| [13] | IEEE Communications Surveys & Tutorials, 2016 | `10.1109/COMST.2015.2494502` | ML/DM IDS survey |
| [14] | IEEE TETCI, 2018 | `10.1109/TETCI.2017.2772792` | Deep-learning IDS |
| [15] | NDSS, 2018 | `10.14722/ndss.2018.23204` | Online autoencoder anomaly detection |
| [16] | IEEE MilCIS, 2015 | `10.1109/MILCOM.2015.7357948` | UNSW-NB15 dataset |
| [17] | IEEE CISDA, 2009 | `10.1109/CISDA.2009.5356528` | KDD'99 dataset limitations |
| [18] | Journal of Network and Computer Applications, 2013 | `10.1016/j.jnca.2012.09.004` | IDS review |
| [19] | ACM KDD, 2016 | `10.1145/2939672.2939778` | LIME explanations |
| [20] | Pattern Recognition, 2018 | `10.1016/j.patcog.2018.07.023` | Adversarial ML risks |
| [21] | NeurIPS 2020 | Official NeurIPS proceedings page | RAG and external knowledge |
| [22] | USENIX Security, 2022 | Official USENIX proceedings page | ML evaluation pitfalls |

## Summary

- Uploaded papers analyzed: 11
- Additional external papers added: 11
- Total references: 22
- External DOI/official publication links verified: 11
- Peer-reviewed/formally published external sources: 11
- External conference papers: 7
- External journal papers: 4
- External preprints: 0
- Uploaded theses, manuscripts, reviews, and conceptual papers are identified as such rather than upgraded into experimental evidence.

## Quality checks

For each external item, title, authors, year, venue, and DOI or official proceedings page were checked before citation. Each external item is cited in the manuscript. The uploaded PDFs remain the primary literature base, but their venue and experimental completeness vary; the manuscript does not silently upgrade a thesis, manuscript, review, or conceptual article into a peer-reviewed experimental result.
