# app/main.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from graph.graph_builder import create_graph


def read_incident_text() -> str:
    """
    Lee el texto del incidente desde stdin hasta encontrar una línea 'END'.
    Permite pegar texto libre o JSON.
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
    # 1) Leer incidente desde stdin
    incident_text = read_incident_text()

    if not incident_text.strip():
        print("No se ha introducido texto de incidente. Saliendo.")
        return

    # 2) Construir grafo y estado inicial
    graph = create_graph()
    initial_state = {"input_text": incident_text}

    # 3) Ejecutar grafo
    result = graph.invoke(initial_state)

    # 4) Obtener informe final
    report_text = result.get("report_text", "")
    report_json = result.get("report", {})

    # 5) Mostrar informe estructurado en consola
    print("\n=== FINAL STRUCTURED REPORT (TEXT) ===\n")
    print(report_text)

    # 6) Guardar en ficheros (txt + json) con timestamp en el nombre
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    # Timestamp tipo 2025-12-01_17-43-22
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    txt_path = out_dir / f"incident_report_{ts}.txt"
    json_path = out_dir / f"incident_report_{ts}.json"

    txt_path.write_text(report_text, encoding="utf-8")
    json_path.write_text(
        json.dumps(report_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n[+] Informe guardado en:")
    print(f"    - {txt_path}")
    print(f"    - {json_path}")


if __name__ == "__main__":
    main()
