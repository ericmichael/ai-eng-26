#!/bin/bash
# Build a custom ext2 image for CheerpX
# Requires: buildah, podman, e2fsprogs (for mkfs.ext2)

set -e

IMAGE_NAME="${1:-cheerpximage}"
CONTAINER_NAME="${IMAGE_NAME}-container"
OUTPUT_FILE="${2:-custom.ext2}"
IMAGE_SIZE="${3:-600M}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="${SCRIPT_DIR}/.tmpfs"

echo "=== Building CheerpX Custom Image ==="
echo "Image name: $IMAGE_NAME"
echo "Output file: $OUTPUT_FILE"
echo "Image size: $IMAGE_SIZE"
echo

# Step 1: Build the Docker image
echo "[1/6] Building Docker image..."
buildah build -f "${SCRIPT_DIR}/Dockerfile" --dns=none --platform linux/i386 -t "$IMAGE_NAME"

# Step 2: Create a container from the image
echo "[2/6] Creating container..."
podman rm -f "$CONTAINER_NAME" 2>/dev/null || true
podman create --name "$CONTAINER_NAME" "$IMAGE_NAME"

# Step 3: Create temp directory for filesystem
echo "[3/6] Preparing filesystem directory..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

# Step 4: Copy filesystem from container
echo "[4/6] Extracting filesystem from container..."
podman unshare podman cp "${CONTAINER_NAME}:/" "$TEMP_DIR/"

# Step 5: Create ext2 image
echo "[5/6] Creating ext2 image..."
podman unshare mkfs.ext2 -b 4096 -d "$TEMP_DIR/" "${SCRIPT_DIR}/${OUTPUT_FILE}" "$IMAGE_SIZE"

# Step 6: Cleanup
echo "[6/6] Cleaning up..."
podman rm -f "$CONTAINER_NAME"
buildah rmi "$IMAGE_NAME" 2>/dev/null || true
rm -rf "$TEMP_DIR"

echo
echo "=== Done! ==="
echo "Created: ${SCRIPT_DIR}/${OUTPUT_FILE}"
echo
echo "To use with CheerpX, serve the file and load it with:"
echo "  CheerpX.Linux.create({ imageUrl: 'http://localhost:8000/${OUTPUT_FILE}' })"
