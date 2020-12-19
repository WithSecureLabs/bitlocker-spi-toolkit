#!/bin/bash
KEY=$1
BITLOCKER_DEVICE=${2:-/dev/bitlocker} 

if [ -b $BITLOCKER_DEVICE ]; then
    # Create the VMK file
    VMK_FILE=$(mktemp)
    echo $KEY | xxd -r -p > $VMK_FILE

    # Mount the drive
    while true; do
        read -p "[+] Mount as read only? [Yn] " yn
        case $yn in
            [Yy]|"" )
                READONLY=1
                break;
                ;;
            [Nn] )
                echo "[+] Mounting drive as READ-WRITE"
                READONLY=0
                break;
                ;;
        esac
    done

    FUSE_PATH=$(mktemp -d)
    DISK_PATH=$(mktemp -d)

    [ $READONLY = 1 ] && DIS_FLAGS="-r" || DIS_FLAGS=""
    dislocker-fuse -K $VMK_FILE $BITLOCKER_DEVICE $DIS_FLAGS -- $FUSE_PATH || \
        { echo "Error: Could not decrypt the volume" 1>&2 ; exit 1; }

    [ $READONLY = 1 ] && NTFS_FLAGS="-o ro" || NTFS_FLAGS=""
    ntfs-3g $NTFS_FLAGS "$FUSE_PATH/dislocker-file" "$DISK_PATH" || \
        { echo "Error: Could not mount the decrypted volume" 1>&2 ; exit 1; }

    # Drop to a shell
    echo "[+] Succesfully decrypted and mounted the drive"
    echo "[+] Dropping to a shell, run exit to unmount"
    bash --rcfile <(echo "PS1='\w \$ '; cd $DISK_PATH;") -i

    # Clean
    echo "[+] Unmounting the drive"
    umount $DISK_PATH
    umount $FUSE_PATH
    rm $VMK_FILE
else
    echo Error: $BITLOCKER_DEVICE not presented 1>&2
    exit 1
fi
