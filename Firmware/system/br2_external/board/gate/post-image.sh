#!/bin/sh
set -e

BOARD_DIR="${BR2_EXTERNAL_GATE_PATH}/board/gate"

echo "Building data partition image"
support/scripts/genimage.sh -c "${BOARD_DIR}/genimage_data.cfg"

echo "==== POST-IMAGE SCRIPT ===="
echo "BINARIES_DIR: $BINARIES_DIR"

[ -f "$BINARIES_DIR/data.ext4" ] || { echo "ERROR: $BINARIES_DIR/data.ext4 not found"; exit 1; }
[ -d "$BINARIES_DIR/rns" ] || { echo "ERROR: $BINARIES_DIR/rns not found"; exit 1; }

TMP_MNT=$(mktemp -d)
echo "Mounting $BINARIES_DIR/data.ext4 at $TMP_MNT"
sudo mount -o loop "$BINARIES_DIR/data.ext4" "$TMP_MNT"

echo "Copying rns/ into data.ext4..."
sudo cp -a "$BINARIES_DIR/rns/." "$TMP_MNT/"

sync
sudo umount "$TMP_MNT"
rmdir "$TMP_MNT"

echo "data.ext4 populated with rns/ successfully."

echo "Building SD Card image"
support/scripts/genimage.sh -c "${BOARD_DIR}/genimage.cfg"
