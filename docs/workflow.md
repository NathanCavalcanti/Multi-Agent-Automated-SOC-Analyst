## Workflow
```
┌─────────────────┐
│  User Input     │
│  (CLI)          │
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │  Graph │
    └────┬───┘
         │
    ┌────▼──────────────────────────────────┐
    │                                       │
    │  ┌─────────────┐                     │
    │  │ IOC Agent   │ ► Extract IPs,      │
    │  └──────┬──────┘   domains, hashes   │
    │         │                             │
    │  ┌──────▼──────┐                     │
    │  │ MITRE Agent │ ► Map techniques    │
    │  └──────┬──────┘   (validated)       │
    │         │                             │
    │  ┌──────▼──────┐                     │
    │  │  CVE Agent  │ ► Fetch CVEs        │
    │  └──────┬──────┘   from NVD API      │
    │         │                             │
    │  ┌──────▼───────────┐                │
    │  │ Investigation    │ ► DFIR Plan    │
    │  │ Agent            │                │
    │  └──────┬───────────┘                │
    │         │                             │
    │  ┌──────▼──────┐                     │
    │  │ Report Agent│ ► Generate JSON/TXT │
    │  └──────┬──────┘                     │
    └─────────┼─────────────────────────────┘
              │
              ▼
      ┌─────────────────────────┐
      │ /output/                │
      │ - report_timestamp.json │
      │ - report_timestamp.txt  │
      └─────────────────────────┘
```