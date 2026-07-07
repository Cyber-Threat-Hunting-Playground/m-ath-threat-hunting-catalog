### Scenario Title / Use Case

Process Memory Allocation Anomaly Scoring

### Scenario Description

Detect process memory injection techniques such as Process Hollowing, DLL Injection, and reflective DLL loading by isolating processes that exhibit anomalous memory allocation profiles. By monitoring dynamic memory adjustments on endpoints, threat hunters can uncover stealthy implants, packing, and beaconing code that bypass traditional on-disk antivirus checks.

### PEAK M-ATH Sub-process

Clustering

### Model or Statistical Method

- [ ] Supervised Classification (e.g. XGBoost, Random Forest)
- [x] Unsupervised Clustering (e.g. K-Means, DBSCAN)
- [x] Anomaly Detection (e.g. Isolation Forest, Autoencoders)
- [ ] Time-Series / Periodicity Analysis
- [ ] Natural Language Processing (NLP) / LLM
- [ ] Graph / Network Analysis
- [ ] Composite / Risk Scoring
- [ ] Other (Specify details in the next section)

### Model Details / Specifics

Feature extraction from endpoint memory telemetry includes page protection transitions (e.g. RWX/RX allocation status), total allocation sizes, memory page state, and thread start addresses referencing unmapped memory. These features are scored using an Isolation Forest to rank anomalous process allocations, or clustered using DBSCAN to isolate rare execution profiles across host clusters.

### Why does M-ATH apply?

Traditional detection rules struggle with process memory events due to the high volume of legitimate VirtualAlloc and VirtualProtect actions performed by browsers, JIT compilers (e.g., JVM, .NET), and signed software. Model-Assisted Threat Hunting (M-ATH) is required to build baseline behavior models for common processes (e.g., svchost.exe, explorer.exe) and identify instances that deviate from their normal cluster distributions.

### Telemetry & Data Sources Needed

- [ ] Active Directory (AD) logs
- [x] Endpoint Detection & Response (EDR) logs
- [x] Windows Event logs
- [ ] DNS query logs
- [ ] Web server / WAF logs
- [ ] Database (DB) logs
- [ ] NetFlow / Network traffic logs
- [ ] VPN / Remote access logs
- [ ] Threat Intelligence telemetry (e.g. VirusTotal)

Windows Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess); Microsoft Defender for Endpoint (MDE) DeviceEvents (ActionTypes: CreateRemoteThreadApiCall, NtMapViewOfSectionRemoteApiCall, QueueUserApcApiCall, OpenProcessApiCall, VirtualAllocApiCall, VirtualProtectApiCall); CrowdStrike Falcon Event Streams (event_simpleName: InjectedThread, ProcessRollup2); SentinelOne Deep Visibility (event.type: Remote Thread Creation, Open Remote Process Handle, Process Modification); or OS-native memory allocation events (e.g., Event Tracing for Windows - ETW).

### References / Source

MITRE ATT&CK T1055 (Process Injection), elastic guide to threat hunting in-memory detection.
