#!/bin/bash
# Start Jupyter Notebook with headers required for CheerpX (SharedArrayBuffer)

jupyter notebook \
    --NotebookApp.tornado_settings='{"headers": {"Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp"}}' \
    "$@"
