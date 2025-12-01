# app/config.py
from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from groq import Groq

# Cargar variables de entorno desde .env
load_dotenv()

# Modelo por defecto de Groq (puedes sobreescribir con variable de entorno GROQ_MODEL)
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Cliente Groq singleton
_GROQ_CLIENT: Optional[Groq] = None


def get_groq_client() -> Groq:
    """
    Devuelve una instancia única (singleton) del cliente Groq.
    Lanza RuntimeError si GROQ_API_KEY no está definida.
    """
    global _GROQ_CLIENT

    if _GROQ_CLIENT is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY no está definida. "
                "Configura tu archivo .env o una variable de entorno del sistema."
            )
        _GROQ_CLIENT = Groq(api_key=api_key)

    return _GROQ_CLIENT


def call_llm(
    messages: List[Dict[str, str]],
    temperature: float = 0.1,
) -> str:
    """
    Encapsula la llamada al modelo de Groq.
    Devuelve siempre un string de contenido.
    """
    client = get_groq_client()

    completion = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        temperature=temperature,
    )

    content = completion.choices[0].message.content
    return content or ""


def extract_json_block(text: str) -> str:
    """
    Extrae el bloque JSON de un texto, aunque venga envuelto en ```json ... ```.

    - Busca el primer '{' y el último '}'.
    - Devuelve la subcadena entre ellos (incluidos).
    - Si no encuentra, devuelve el texto original.
    """
    if not text:
        return text

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and start < end:
        return text[start : end + 1]

    return text
