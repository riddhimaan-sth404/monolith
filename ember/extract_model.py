#!/usr/bin/env python3
"""Extract the text portion from LightGBM pickled/packaged model files."""
import sys
from pathlib import Path

def extract_text_model(input_path_str, output_path=None):
    input_path = Path(input_path_str)
    data = input_path.read_bytes()

    # Find the text portion marker
    text_start = data.find(b'tree\nversion=v4')
    if text_start < 0:
        text_start = data.find(b'tree\nversion=v')
    if text_start < 0:
        text_start = data.find(b'Tree=')
    if text_start < 0:
        text_start = data.find(b'[Tree:')
    if text_start < 0:
        print(f"No text model found in {input_path}")
        return None

    # Find end of text portion
    text_end = data.find(b'end of parameters', text_start)
    if text_end < 0:
        text_end = len(data)
    else:
        text_end += len(b'end of parameters')

    text_model = data[text_start:text_end]

    # Find pandas_categorical line and include it
    pc = text_model.find(b'pandas_categorical:')
    if pc >= 0:
        nl = text_model.find(b'\n', pc)
        if nl > 0:
            text_model = text_model[:nl+1]
        else:
            text_model = text_model[:pc + len(b'pandas_categorical:null\n')]

    if output_path is None:
        output_path = input_path.with_suffix('.txt')

    Path(output_path).write_bytes(text_model)
    print(f"Extracted text model ({len(text_model)} bytes) -> {output_path}")
    return output_path


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <model_file> [output_file]")
        sys.exit(1)
    extract_text_model(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
