"""
Shared Gemini client for all OWASP LLM examples.
Loads API key from .env — never hardcode credentials.

Uses google-genai SDK (current) not google-generativeai (deprecated).
"""

import os
import logging
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-2.5-flash"


def get_client() -> genai.Client:
    """
    Returns a configured Gemini client.
    Raises EnvironmentError if GEMINI_API_KEY is not set.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY not found. "
            "Copy .env.example to .env and add your key."
        )
    return genai.Client(api_key=api_key)


def chat(
    system_prompt: str,
    user_message: str,
    model: str = None,
    max_tokens: int = 512,
) -> str:
    """
    Single-turn chat with system prompt and user message.
    Returns the text response string.

    Args:
        system_prompt: Instructions for the model role and constraints
        user_message:  The user input (sanitized before passing here)
        model:         Gemini model name — defaults to GEMINI_MODEL env var
                       or gemini-2.0-flash
        max_tokens:    Maximum output tokens
    """
    client = get_client()
    model_name = model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL)

    response = client.models.generate_content(
        model=model_name,
        contents=user_message,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            max_output_tokens=max_tokens,
        ),
    )
    return response.text
