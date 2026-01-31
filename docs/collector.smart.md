# smart collector

The smart collector exposes disk health metrics by invoking `smartctl.exe` from the [smartmontools](https://www.smartmontools.org/) package.

This collector requires `smartctl` to be installed on the host and accessible on the PATH or configured via `--collector.smart.smartctl-path`.

## Flags

### `--collector.smart.smartctl-path`
Path to the `smartctl` executable. Defaults to `smartctl.exe`.

### `--collector.smart.extra-args`
Comma-separated list of extra arguments to pass to `smartctl` when querying devices. Useful for options like `-n standby` to avoid spinning up disks.

## Metrics

| Name                                                     | Description                                                       | Type  | Labels |
|----------------------------------------------------------|-------------------------------------------------------------------|-------|--------|
| `windows_smart_info`                                     | SMART device information reported by smartctl                     | gauge | `model`, `model_family`, `serial_number`, `firmware_version`, `protocol`, `type` |
| `windows_smart_health_status`                            | SMART overall-health self-assessment test status                  | gauge | `model`, `status` |
| `windows_smart_temperature_celsius`                      | Current device temperature in Celsius                             | gauge | `model` |
| `windows_smart_power_on_hours`                           | Total number of hours the device has been powered on              | gauge | `model` |
| `windows_smart_power_cycles`                             | Total number of power cycles                                      | gauge | `model` |
| `windows_smart_reallocated_sectors_total`                | Number of reallocated sectors (ATA SMART attribute 5)             | gauge | `model` |
| `windows_smart_pending_sectors_total`                    | Number of pending sectors awaiting reallocation (ATA attribute 197) | gauge | `model` |
| `windows_smart_offline_uncorrectable_sectors_total`      | Number of offline uncorrectable sectors (ATA attribute 198)       | gauge | `model` |
| `windows_smart_nvme_data_units_read_total`               | Number of NVMe data units read                                    | gauge | `model` |
| `windows_smart_nvme_data_units_written_total`            | Number of NVMe data units written                                 | gauge | `model` |
| `windows_smart_nvme_percentage_used`                     | NVMe percentage used (wear indicator)                             | gauge | `model` |
| `windows_smart_nvme_media_errors_total`                  | NVMe media errors                                                 | gauge | `model` |
| `windows_smart_nvme_unsafe_shutdowns_total`              | NVMe unsafe shutdowns                                             | gauge | `model` |
| `windows_smart_nvme_error_log_entries_total`             | NVMe error log entries                                            | gauge | `model` |

## Example usage

Enable the collector and keep disks in standby when possible:

```powershell
windows_exporter.exe --collectors.enabled="[defaults],smart" --collector.smart.extra-args="-n,standby"
```
