#!/bin/sh
set -eu

mkdir -p /run/software-tpm
chmod 700 /run/software-tpm
exec swtpm socket \
  --tpm2 \
  --tpmstate dir=/run/software-tpm \
  --server type=tcp,port=2321,bindaddr=0.0.0.0 \
  --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
  --flags not-need-init,startup-clear
