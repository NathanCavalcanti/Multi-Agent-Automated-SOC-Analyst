# app/main.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from graph.graph_builder import create_graph


def read_incident_text() -> str:
    """
    Reads incident text from stdin until 'END' line is found.
    Allows pasting free text or JSON.
    """
    print("=== Running SOC Multi-Agent System ===\n")
    print("Paste your incident text (JSON or plain text).")
    print("When finished, type END and press Enter.\n")

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)

    return "\n".join(lines)


def main() -> None:
    # 1) Read incident from stdin
    incident_text = read_incident_text()

    if not incident_text.strip():
        print("No incident text provided. Exiting.")
        return

    # 2) Build graph and initial state
    graph = create_graph()
    initial_state = {"input_text": incident_text}

    # 3) Execute graph with LLM error handling
    try:
        result = graph.invoke(initial_state)
    except RuntimeError as e:
        msg = str(e)

        if msg.startswith("LLM_RATE_LIMIT:"):
            print("\n[ERROR] Cannot complete analysis with LLM.")
            print("Reason: Groq model usage/token limit reached "
                  "(e.g., free plan or on_demand with no quota).")
            print("Provider detail:")
            print(f"  {msg}")
            print("\nPossible actions:")
            print("  - Wait for daily token limit reset.")
            print("  - Reduce input incident size.")
            print("  - Use another Groq API key with quota.")
            print("  - Switch to a lighter model if available.")
            return

        if msg.startswith("LLM_API_ERROR:"):
            print("\n[ERROR] Groq API returned an error processing the request.")
            print("Detail:")
            print(f"  {msg}")
            print("\nCheck Groq service status or retry later.")
            return

        if msg.startswith("LLM_ERROR:") or msg.startswith("LLM_UNKNOWN_ERROR:"):
            print("\n[ERROR] An error occurred calling the Groq model.")
            print("Detail:")
            print(f"  {msg}")
            print("\nCheck your GROQ_API_KEY configuration, the configured model "
                  "and your Internet connection.")
            return

        # Generic RuntimeError not from LLM_*
        print("\n[ERROR] An error occurred during analysis execution:")
        print(f"  {msg}")
        return

    except Exception as e:
        # Any other unexpected error (bug, etc.)
        print("\n[ERROR] Unexpected error during SOC Multi-Agent System execution.")
        print(f"Technical detail: {e}")
        print("Check logs or run in debug mode for more information.")
        return

    # 4) Get final report
    report_text = result.get("report_text", "")
    report_json = result.get("report", {})

    # 5) Show structured report in console
    print("\n=== FINAL STRUCTURED REPORT (TEXT) ===\n")
    print(report_text)

    # 6) Save to files (txt + json) with timestamp
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    txt_path = out_dir / f"incident_report_{ts}.txt"
    json_path = out_dir / f"incident_report_{ts}.json"

    txt_path.write_text(report_text, encoding="utf-8")
    json_path.write_text(
        json.dumps(report_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n[+] Report saved to:")
    print(f"    - {txt_path}")
    print(f"    - {json_path}")


if __name__ == "__main__":
    main()
