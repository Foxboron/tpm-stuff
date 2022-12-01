#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

export tpm_dir=/var/tmp/vtpm
modprobe tpm_vtpm_proxy

if [ -d ${tpm_dir} ]
then
    echo "Found existing ${tpm_dir}"
    swtpm chardev --tpm2 --vtpm-proxy --tpmstate dir=$tpm_dir -d
else
    echo "Error: Directory ${tpm_dir} does not exists."
    mkdir ${tpm_dir}
    swtpm_setup --tpm2 \
        --tpmstate $tpm_dir \
        --createek --allow-signing --decryption --create-ek-cert \
        --create-platform-cert \
        --display
    swtpm chardev --tpm2 --vtpm-proxy --tpmstate dir=$tpm_dir -d
fi

export TPM2TOOLS_TCTI="device:/dev/tpm0"
