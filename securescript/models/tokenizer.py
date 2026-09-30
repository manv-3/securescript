"""
SecureScript Character-Level Tokenizer for Deep Learning.

Preserves syntactic delimiters, quotes, brackets, and structural markup
without out-of-vocabulary losses common in natural language tokenizers.
"""

from __future__ import annotations

import json
import os
import string
from typing import Dict, List, Optional


class CharTokenizer:
    """
    Character-level tokenizer optimized for script and payload tokenization.
    """

    PAD_TOKEN = "<PAD>"
    UNK_TOKEN = "<UNK>"

    def __init__(self, max_length: int = 200):
        self.max_length = max_length
        self.char_to_idx: Dict[str, int] = {
            self.PAD_TOKEN: 0,
            self.UNK_TOKEN: 1,
        }
        self.idx_to_char: Dict[int, str] = {
            0: self.PAD_TOKEN,
            1: self.UNK_TOKEN,
        }

        # Build initial vocabulary with standard printable characters
        printable = string.printable  # digits, ascii_letters, punctuation, whitespace
        for idx, char in enumerate(printable, start=2):
            self.char_to_idx[char] = idx
            self.idx_to_char[idx] = char

    @property
    def vocab_size(self) -> int:
        return len(self.char_to_idx)

    def encode(self, text: str) -> List[int]:
        """Encodes text to a fixed-length list of character indices."""
        indices = [self.char_to_idx.get(char, 1) for char in text[:self.max_length]]
        # Pad if shorter than max_length
        if len(indices) < self.max_length:
            indices += [0] * (self.max_length - len(indices))
        return indices

    def decode(self, indices: List[int]) -> str:
        """Decodes indices back to string (ignoring padding)."""
        chars = [self.idx_to_char.get(idx, "") for idx in indices if idx != 0]
        return "".join(chars)

    def save(self, file_path: str) -> None:
        """Saves tokenizer state to JSON."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        data = {
            "max_length": self.max_length,
            "char_to_idx": self.char_to_idx,
            "idx_to_char": {str(k): v for k, v in self.idx_to_char.items()}
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self, file_path: str) -> None:
        """Loads tokenizer state from JSON."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.max_length = data["max_length"]
        self.char_to_idx = data["char_to_idx"]
        self.idx_to_char = {int(k): v for k, v in data["idx_to_char"].items()}
