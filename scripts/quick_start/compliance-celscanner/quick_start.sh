#!/bin/bash
# Setup the environment
# export bin path
export PATH=$PATH:$PWD/bin

# Install the plugin
make build

# Copy the plugin to the /usr/libexec/complytime/plugins
sudo cp bin/celscanner-plugin /usr/libexec/complytime/plugins/

# Create /usr/share/complytime
sudo mkdir -p /usr/share/complytime


# Copy over the sample files
sudo cp -r docs/samples/compliance-celscanner/* /usr/share/complytime/


# Replace the sha256 in the plugin manifest
sed -i 's/REPLACE_ME_SHA256/'$(sha256sum bin/celscanner-plugin | awk '{print $1}')'/g' /usr/share/complytime/plugins/c2p-celscanner-manifest.json > /dev/null 2>&1 || true


# Create a new assessment plan
complyctl plan ocp4-cis

# run the assessment
complyctl scan