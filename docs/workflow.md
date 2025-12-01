flowchart TD

    U[Analista SOC\n(pega incidente en terminal)] --> M[app/main.py]

    M -->|input_text| G[LangGraph\nSOCState + graph_builder]

    subgraph Agents / Nodes
        A1[ IOC Agent\n(agents/ioc_agent.py) ]
        A2[ MITRE Agent\n(agents/mitre_agent.py) ]
        A3[ CVE Agent\n(agents/cve_agent.py) ]
        A4[ Investigation Agent\n(agents/investigation_agent.py) ]
        A5[ Report Agent\n(agents/report_agent.py) ]
    end

    G --> A1
    G --> A2
    G --> A3
    G --> A4

    A1 -->|iocs JSON| G
    A2 -->|ttps JSON\n(Enterprise MITRE / LLM supposition)| G
    A3 -->|cves JSON\n(desde NVD)| G
    A4 -->|investigation_plan JSON| G

    G --> A5
    A5 -->|report JSON + report_text| M

    subgraph External Services
        LLM[Groq LLM\n(llama-3.3-70b, etc.)]
        MITRE[GitHub MITRE CTI\nenterprise-attack.json]
        NVD[NVD API\ncves/2.0]
    end

    A1 --> LLM
    A2 --> LLM
    A3 --> LLM
    A3 --> NVD
    A4 --> LLM

    A2 --> MITRE
    MITRE -->|data/enterprise-attack.json\n(fallback local)| A2

    M -->|guarda| F1[output/incident_report_YYYY-MM-DD_HH-MM-SS.txt]
    M -->|guarda| F2[output/incident_report_YYYY-MM-DD_HH-MM-SS.json]
