---
lang: "en"
title: "Model-Assisted Threat Hunting (M-ATH) with the PEAK Framework | Splunk"
description: "Welcome to the third entry in our introduction to the PEAK Threat Hunting Framework! Taking our detective theme to the next level, imagine a tough case where you need to call in a specialized investigator. For these unique cases, we can use algorithmically-driven approaches called Model-Assisted Threat Hunting (M-ATH)."
url: "https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html"
publisher: "Splunk"
author: "Ryan Fetterman"
date: "2026-03-26T04:51:49.000Z"
word_count: 2789
reading_time: "11 min read"
---

## Table of Contents

- [M-ATH & the PEAK Threat Hunting Framework](#m-ath--the-peak-threat-hunting-framework)
  - [When & Why to use M-ATH](#when--why-to-use-m-ath)
- [Model-Assisted Threat Hunting with PEAK](#model-assisted-threat-hunting-with-peak)
  - [Phase 1. Prepare: Plan your Approach](#phase-1-prepare-plan-your-approach)
  - [Phase 2. Execute: Experimentation Time](#phase-2-execute-experimentation-time)
  - [Phase 3. Act: Wrapping Up the Investigation](#phase-3-act-wrapping-up-the-investigation)
- [Applied M-ATH Examples](#applied-m-ath-examples)
- [Conclusion](#conclusion)
- [About Splunk](#about-splunk)

---

Welcome to another entry in our PEAK Threat Hunting Framework and we are taking our detective theme to the next level.

Imagine a tough case where you need to call in a specialized investigator — even Sherlock depended on Watson from time to time! For these unique cases, we can use algorithmically-driven approaches called **Model-Assisted Threat Hunting (M-ATH)**.

In this article, we’ll look at M-ATH in detail. This method uses algorithms to find leads for [threat hunting](https://www.splunk.com/en_us/blog/learn/threat-hunting.html "threat hunting"), enabling more advanced and experimental hunts. These methods include machine learning approaches like clustering, classification, or anomaly detection.

*(This article is part of our [PEAK Threat Hunting Framework series](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html "PEAK Threat Hunting Framework series"). Explore the framework to unlock happy hunting!)*

## M-ATH & the PEAK Threat Hunting Framework

The PEAK Framework identifies three primary types of hunts: [Hypothesis-Driven Hunts](https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html "Hypothesis-Driven Hunts"), [Baseline Hunts](https://www.splunk.com/en_us/blog/security/peak-baseline-hunting.html "Baseline Hunts"), and Model-Assisted Threat Hunts (M-ATH).

M-ATH is categorized separately because it can facilitate baselining or hypothesis-driven hunting. Defining the adversary activity you are looking for, as in Hypothesis-Driven Hunting, can help you select your analysis method. Alternatively, you can apply M-ATH methods as a means to better understand your data, like using clustering to profile differences in user groups.

Output from M-ATH models can provide direct threat hunting leads, feed into an enrichment pipeline to support further investigation, or even contribute to your organization’s risk-model in a [Risk-Based Alerting](https://www.splunk.com/en_us/blog/security/risk-based-alerting-the-new-frontier-for-siem.html "Risk-Based Alerting") setup!

### When & Why to use M-ATH

Like a good detective establishing motive, we need to understand *when* and *why* to use this method. M-ATH is a good choice when a hunt topic fits the right criteria:

- **Simpler methods aren’t accurate enough.** Always evaluate established methods first! If an existing approach works well (e.g., combination of searching, filtering, sorting, stacking), consider whether a more resource-intensive approach is needed.
- **Classes of behavior (benign/malicious) are, or can be, easily labeled.** This enables some methods like supervised classification. These can also be used outright for threat detection in high confidence scenarios, but aren’t always going to scale well or justify the resource investment of an always-on detection.
- **The data is high-volume, and/or is difficult to summarize or reduce.** These problems may be well-suited to dimensionality reduction and unsupervised clustering.
- **You have high confidence in identification of events, but accuracy of classification is difficult.** In these cases, an analyst-in-the-loop is often required to make a final classification decision. Since all the attacker behaviors we’re interested in aren’t inherently malicious, this makes for good threat hunting criteria in general.

**Invest Wisely**

A good M-ATH problem should always meet at least criteria \#1 — *simpler methods aren't effective enough*. Even better, though, is that the more criteria that fit, the more likely that you're on the right path!

All security operations depend on the use of limited resources, most critically, analyst time! We start with simpler and established methods first, because M-ATH approaches can require more significant expertise and resources to develop, maintain, and [interpret the output](https://www.splunk.com/en_us/blog/learn/outputs-vs-outcomes.html "interpret the output"). However, if done correctly, models can...

- Result in high-fidelity detections.
- Provide valuable enrichment around risk.
- Quickly automate sequences of complex logic for future hunting processes.

*Choose your tools carefully!*

## Model-Assisted Threat Hunting with PEAK

Like our other PEAK hunting methods, M-ATH is underpinned by the core phases of Prepare, Execute, and Act. It is within these phases where the M-ATH magic happens:

### Phase 1. Prepare: Plan your Approach

The “Prepare” phase is where you do all the things necessary to maximize your chances of a successful hunt; Establish your problem, your approach, and the resources available to help you succeed!

**Select Topic:** Our topic can take the form of an exploratory question about our data, or a hypothesis about adversary activity that requires a more advanced method. For example, let’s imagine we’re hunting for adversary behavior using [dictionary-based Domain Generation Algorithms](https://link.springer.com/article/10.1007/s42979-021-00507-w "dictionary-based Domain Generation Algorithms") for the Command-and-Control channel. Let’s see if this meets our entry criteria for a M-ATH hunt:

- ***Simpler methods aren’t accurate enough*** \*\*:\*\* This problem can be hard to detect accurately with simpler methods because dictionary-based domains blend in by maintaining similar lexical characteristics as legitimate sites.
- ***Classes of behavior (benign/malicious) are, or can be, easily labeled*** \*\*:\*\* Data exists with labeled classes of legitimate and malicious data, making this a candidate for supervised classification.
- ***The data is high volume, and/or is difficult to summarize or reduce*** \*\*:\*\* Network/web traffic is high volume and multidimensional. If we hunt for this retroactively, we can meaningfully filter out our organization’s most popular domains and reduce our processing overhead.
- ***You have high confidence in identification of events, but accuracy of classification is difficult.*** We won’t know until we test it, but it is likely that given the volume of events here and the nature of this threat, a model should be able to meaningfully reduce our data to a set of probable dictionary-DGA domains, and that human classification or some additional hunting will be needed to make final classification of the threat.

**Research Topic:** Gather all the information you can to become a subject-matter expert. This includes:

- Diving into the literature, comparing existing detection methods and their accuracy.
- Checking for existing open source information, models, code, datasets.
- Finding out how your organization monitors and detects malicious and suspicious domains and what detection gaps you might have.

**Identify Datasets:** Understanding the methods and resources available to hunt for the threat will help you understand the level of effort that may be required and the approaches possible in the next step. For our dictionary DGA use case, we would look for datasets labeled with [legitimate domains](https://github.com/mozilla/cipherscan/tree/master/top1m "legitimate domains"), and datasets labeling [dictionary-DGA domains](https://github.com/baderj/domain_generation_algorithms/tree/master "dictionary-DGA domains").

**Select Algorithms:** Algorithm selection includes a broad category of choices. There are many options here and we will cover some use cases of how they are applied in the examples section. Some examples of the most popular families of algorithms include:

- **<u>Classification</u>**: Classifier algorithms predict the value of a categorical field. Classification is a supervised deep or shallow learning method.
- **<u>Clustering</u>**: Clustering is the grouping of data points. Results will vary depending upon the clustering algorithm used. Clustering algorithms differ in how they determine if data points are similar and should be grouped.
- **<u>Time Series Analysis</u>**: Forecasting algorithms, also known as time series analysis, provide methods for analyzing time series data in order to extract meaningful statistics and other characteristics of the data, and forecast its future values.
- **<u>Anomaly Detection</u>:** Anomaly detection algorithms use statistical approaches to find outliers in numerical or categorical fields.

These are available in the [Machine Learning Toolkit (MLTK)](https://splunkbase.splunk.com/app/2890 "Machine Learning Toolkit (MLTK)"), or through Python-based data science libraries using the [Splunk app for Data Science and Deep Learning (DSDL)](https://splunkbase.splunk.com/app/4607 "Splunk app for Data Science and Deep Learning (DSDL)"). In our dictionary-DGA example, the literature suggests that supervised learning, and more specifically deep learning approaches are well-suited.

### Phase 2. Execute: Experimentation Time

The “Execute” phase is where you develop and experiment with your model, as well as implement your hunt plan.

**Gather Data:** With your plan established, it's time to collect the evidence and bring it all back into one place for analysis. In some cases, this may have already happened (for example, if you’re already ingesting the network logs you need into a Splunk index). In other cases, you might have to identify the specific server(s) and locations on disk from which to collect the data.

**Pre-Process Data:** Sadly, the data we need is often not quite ready for analysis. This can apply to the data we’ve collected, as well as any data we’re preparing to use for training if a supervised method applies. We may need to:

- Convert it to a different format (e.g., JSON to CSV)
- Normalize equivalent logs from two different solutions into a common schema
- Throw out records with missing or nonsensical values
- Encode categorical fields
- Label data

For our sample dictionary-DGA hunt, this step would include encoding domains into numerical representations for processing by a deep learning network. Making sure that data is clean and consistent will make the analysis much easier!

**Develop Model:** Now it’s time to dive into the data to look for patterns, anomalies, or evidence of adversary activity. This step is the most flexible, depending on the approach and algorithm you’ve selected. We’ll have more to say about specific M-ATH approaches and examples in future blogs, but for now, keep in mind the possibility of reusing code or hunting models across different threats. For example, many problems will repeat the same necessary steps, like cleaning data, extracting fields, tuning model parameters, etc. The more hunting you do with M-ATH, the more versatility you will develop, and the better you’ll be at putting together the right pieces for the job. For our deep learning DGA example, development would include instantiating a neural network, and feeding in our encoded features to train a model.

**Refine:** When your analysis reveals new insights or fails to find what you were looking for, don't hesitate to revise. For M-ATH approaches, this step may include testing performance and accuracy of your approach, adjusting algorithms or features, and tuning hyperparameters if machine learning is used. This is a normal and expected part of threat hunting and data science. We don’t always hit the mark the first time, so one or more rounds of refinement will often be necessary. In our example, we could experiment with different deep learning architectures and tune parameters like batch size and training epochs.

**Apply:** When your model has reached an acceptable level of performance and accuracy on test data, it’s time to apply it against your hunting data set. This is where you will likely look to operationalize your model or algorithm through [DSDL](https://docs.splunk.com/Documentation/DSDL/5.0.0/User/ModelWorkflow "DSDL") or MLTK – [\| apply](https://docs.splunk.com/Documentation/MLApp/5.4.0/User/Understandfitandapply "| apply") is the way!

**Analyze:** We’ve applied the model, but we’re not done yet! The assistance we’re getting from the model may just be the first step in finding our interesting leads.In this step, we can use the rest of our hunting toolkit to apply traditional methods to our refined dataset, like filtering, sorting, stacking, clustering, or frequency analysis. Further dictionary-DGA analysis, for example, could enrich the results with reputation analysis or domain registration details, helping the analyst quickly sort through the results and make classification decisions. Lastly, if you find some false positives, consider labeling them and adding them to your training data, revisiting the "refine" step!

**Escalate Critical Findings:** Should you be lucky (or unlucky) enough to find likely or confirmed malicious activity during your hunt, escalate it immediately to the incident response team for swift action.

### Phase 3. Act: Wrapping Up the Investigation

All the detailed planning and expert execution won’t matter if you can’t capture and act on the knowledge gained from your hunt. That’s what the “Act” phase is all about!

**Preserve Hunt:** Don't let your hard work go to waste. Archive your hunt, including the data, notebooks, trained models, tools, and techniques used for future reference or to share with other cyber sleuths.

Many hunt teams use wiki pages to write up each hunt, including links to the data, descriptions of the analysis process, and summaries of key findings or metrics.

**Document Findings:** Write up a detailed report on your findings, data or detection gaps you found, misconfigurations you identified, and of course, any potential incidents you escalated.This is the “so what?” of your entire hunt. These findings, and the actions your security team takes to address them, are one of the key drivers for continuous improvement of your organization’s security posture.

**Create Detections/Notables/Playbooks:** The best models may result in worthwhile detections.This is a best-case scenario, and you may decide these should be run on a regular cadence to produce detection alerts. In other more common situations, your model may get you 80% of the way there. If the activity that is characterized is high-value, you may choose to add events as a contextual risk notable. If this produces too much volume, or doesn’t have meaningful correlative activity from the rest of your risk items, adding some enrichment and putting an analyst in the loop via a repeatable M-ATH playbook can help you close that remaining 20%!

**Re-Add Topic to Backlog:** As hunters, we’ll often uncover new avenues for exploration while we’re already in the midst of a hunt. Stay focused, but take note of those potential new ideas because they can become new topics or hypotheses for future hunting. If your team keeps a slush pile or backlog of potential hunts (and they should!), add them so you can revisit them later.

**Communicate Findings:** Share your discoveries with relevant stakeholders to improve overall security posture. Maybe the findings for each hunt are emailed to the SOC leadership and the owners of the systems/data involved. Perhaps you hold a hunt briefing for the security team once a month.

Find the communication format that works best for your team as well as your stakeholders. After all, knowledge is most powerful when shared.

## Applied M-ATH Examples

Here are some other examples that are well suited for this approach and can help get you started putting M-ATH in motion:

- Supervised Classification:

  - [Suspicious DNS TXT records](https://www.splunk.com/en_us/blog/security/ml-in-security-detect-suspicious-txt-records-using-deep-learning.html "Suspicious DNS TXT records")
  - [DGA Detection](https://www.splunk.com/en_us/blog/security/machine-learning-in-security-deep-learning-based-dga-detection-with-a-pre-trained-model.html "DGA Detection")
  - [Obfuscated PowerShell Detection](https://posts.specterops.io/learning-machine-learning-part-1-introduction-and-revoke-obfuscation-c73033184f0 "Obfuscated PowerShell Detection")

- Unsupervised Clustering:

  - [Visualizing a Space JA3 Signatures with Splunk](https://www.splunk.com/en_us/blog/security/visualising-a-space-of-ja3-signatures-with-splunk.html "Visualizing a Space JA3 Signatures with Splunk")
  - [IP Similarity](https://www.greynoise.io/blog/how-we-built-ip-similarity "IP Similarity")

- Natural Language Processing:

  - [Hunting risky SPL with NLP](https://www.splunk.com/en_us/blog/security/machine-learning-in-security-nlp-based-risky-spl-detection-with-a-pre-trained-model.html "Hunting risky SPL with NLP")
  - [Detecting Suspicious Processes Using Recurrent Neural Networks](https://www.splunk.com/en_us/blog/security/machine-learning-in-security-detecting-suspicious-processes-using-recurrent-neural-networks.html "Detecting Suspicious Processes Using Recurrent Neural Networks")

## Conclusion

Model-Assisted Threat Hunting can help you approach some otherwise hard-to-tackle threats, offer you some creative and experimental methods for broaching new topics, or meaningfully reduce or consolidate complex data before applying more traditional hunting methods.

The outputs of these hunts can lead to ML-based or non-ML threat detections, repeatable threat hunting workflows, or new notables for enriching your risk index in a [Risk-based Alerting](https://www.splunk.com/en_us/blog/security/risk-based-alerting-the-new-frontier-for-siem.html "Risk-based Alerting") framework.

By integrating a solid, data science-backed approach with the [PEAK framework's Prepare, Execute, and Act phases](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html "PEAK framework's Prepare, Execute, and Act phases") to guide you through the process, we can ensure a well-structured, focused, and effective hunt. Stay tuned for more posts on this topic, and the PEAK framework – *M-ATH class is in session!*

*As always, security at Splunk is a family business. Credit to authors and collaborators:* *[David Bianco](mailto:dbianco@splunk.com "David Bianco")*

## About Splunk

The world’s leading organizations rely on Splunk, a Cisco company, to continuously strengthen digital resilience with our unified security and observability platform, powered by industry-leading AI.

Our customers trust Splunk’s award-winning security and observability solutions to secure and improve the reliability of their complex digital environments, at any scale.

[Learn more about Splunk](https://www.splunk.com/en_us/about-us/why-splunk.html)