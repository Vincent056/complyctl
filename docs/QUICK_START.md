# Quick Start

To get started with the `complyctl` CLI, at least one plugin must be installed with a corresponding OSCAL [Component Definition](https://pages.nist.gov/OSCAL/resources/concepts/layer/implementation/component-definition/).

> Note: Some of these steps are manual. The [quick_start.sh](../scripts/quick_start/quick_start.sh) automates the process below.

## Step 1: Install Complyctl

See [INSTALLATION.md](INSTALLATION.md)

## Step 2: Add configuration

After running `complyctl list` for the first time, the complytime
directory should be created under $HOME/.local/share

```markdown
complytime
├── bundles
└── plugins
└── controls
```

You will need an OSCAL Component Definition that defines an OSCAL Component for your target system and an OSCAL Component the corresponding
policy validation plugin. See `docs/samples/` for example configuration for the `myplugin` plugin.

```bash
cp docs/samples/sample-component-definition.json ~/.local/share/complytime/bundles
cp docs/samples/sample-profile.json docs/samples/sample-catalog.json ~/.local/share/complytime/controls
```

## Step 3: Install a plugin

Each plugin requires a plugin manifest. For more information about plugin discovery see [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md).


```bash
plugin_dir="$HOME/.local/share/complytime/plugins"
cp "bin/openscap-plugin" "docs/samples/c2p-openscap-manifest.json" "$plugin_dir"
checksum=$(sha256sum ~/.local/share/complytime/plugins/openscap-plugin | awk '{ print $1 }' )
version=$(bin/complyctl version | head -n1 | awk '{ print $2 }' | sed -E 's/^v([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
sed -i -e "s|checksum_placeholder|$checksum|" -e "s|version_placeholder|$version|" "$plugin_dir/c2p-openscap-manifest.json"
```

## Step 4: Edit plugin configuration (optional)
```bash
mkdir -p /etc/complyctl/config.d
cp ~/.local/share/complytime/plugins/c2p-openscap-manifest.json /etc/complyctl/config.d
```

Edit `/etc/complyctl/config.d/c2p-openscap-manifest.json` to keep only the desired changes. e.g.:
```json
{
  "configuration": [
    {
      "name": "policy",
      "default": "custom_tailoring_policy.xml",
    },
    {
      "name": "arf",
      "default": "custom_arf.xml",
    },
    {
      "name": "results",
      "default": "custom_results.xml",
    }
  ]
}
```

### Using with the openscap-plugin

If using the openscap-plugin, there are two prerequisites:
- **openscap-scanner** package installed
- **scap-security-guide** package installed
