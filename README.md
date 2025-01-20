# MuteEDR

A Windows network traffic control utility that uses the Windows Filtering Platform (WFP) to block outbound network connection of a specific Application.

## Features

- Block outbound network traffic of any Application
- Persistent filters that survive system reboots
- Easy filter removal with unblock command

## ⚠️ Safety Warnings

1. **Physical Access Required**: Ensure you have physical access to the machine before testing
2. **Network Isolation**: This tool can completely block ALL network traffic
3. **Testing Environment**: Always test in a controlled environment first
4. **Backup Plan**: Have a way to remove filters if remote access is lost
5. **Administrative Rights**: Requires administrative privileges to manage WFP filters

## Usage

### Block Network Traffic

To block network traffic for a specific process, run the following command:

```bash
MuteEDR block <path_to_process>
```

### Unblock Network Traffic

To remove all filters and restore normal network traffic, run the following command:

```bash
MuteEDR unblock
```

## Technical Details

### Network Layers
The tool creates filters at the following WFP layers:
- `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` (Outbound connections)

### Implementation
- Uses Windows Filtering Platform (WFP) API
- Creates persistent filters that survive system reboots
- Implements custom provider for filter management
- Written in Rust for memory safety and performance (and being FUD :))


## Disclaimer

This tool is provided as-is without any warranties. Users are responsible for any consequences of using this tool. Always test in a controlled environment first and ensure you have a way to recover access if needed.

## Author

GrosMinet123

## License

Apache 2.0
