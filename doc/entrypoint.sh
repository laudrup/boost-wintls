#!/bin/bash -eux

# Generates the HTML documentation for the boost-wintls project.
# Intended to be run from a Docker container

[[ -z "${GITHUB_WORKSPACE}" ]] && { echo "GITHUB_WORKSPACE must be set to the repository root"; exit 1; }

cd /tmp
git clone -b develop https://github.com/boostorg/boost.git boost-root
cd boost-root
git submodule update --init tools/boostbook
git submodule update --init tools/boostdep
git submodule update --init tools/docca
git submodule update --init tools/quickbook
ln -s ${GITHUB_WORKSPACE} libs/wintls
python tools/boostdep/depinst/depinst.py ../tools/quickbook
./bootstrap.sh
./b2 headers
echo "using doxygen ; using boostbook ; using saxonhe ;" > ~/user-config.jam
./b2 -j3 libs/wintls/doc//boostrelease
