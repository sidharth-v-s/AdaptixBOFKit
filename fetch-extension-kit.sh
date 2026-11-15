#!/usr/bin/env bash
#
# Optional: fetch and build the official Adaptix Extension-Kit next to this
# extension.  That project supplies the heavy BOFs (nanodump, Kerbeus,
# DCSync, ADCS, execute-assembly, injection suites, lateral movement, ...).
#
# It is GPLv3 and is not part of AdaptixBOFKit's source tree or license.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p vendor

if [ ! -d vendor/Extension-Kit/.git ]; then
    git clone --depth 1 https://github.com/Adaptix-Framework/Extension-Kit.git vendor/Extension-Kit
else
    git -C vendor/Extension-Kit pull --ff-only
fi

make -C vendor/Extension-Kit -j"$(nproc)"

echo
echo "Official Extension-Kit built."
echo "Load it in Adaptix with:"
echo "  $(pwd)/vendor/Extension-Kit/extension-kit.axs"
