// SPDX-License-Identifier: Apache-2.0
//
// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package smart

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
)

const Name = "smart"

type Config struct {
	SmartctlPath string   `yaml:"smartctl-path"`
	ExtraArgs    []string `yaml:"extra-args"`
}

//nolint:gochecknoglobals
var ConfigDefaults = Config{
	SmartctlPath: "smartctl.exe",
	ExtraArgs:    []string{},
}

type Collector struct {
	config Config

	logger       *slog.Logger
	smartctlPath string

	infoDesc                 *prometheus.Desc
	healthStatusDesc         *prometheus.Desc
	temperatureDesc          *prometheus.Desc
	powerOnHoursDesc         *prometheus.Desc
	powerCyclesDesc          *prometheus.Desc
	reallocatedSectorsDesc   *prometheus.Desc
	pendingSectorsDesc       *prometheus.Desc
	offlineUncorrectableDesc *prometheus.Desc
	nvmeDataUnitsReadDesc    *prometheus.Desc
	nvmeDataUnitsWrittenDesc *prometheus.Desc
	nvmePercentageUsedDesc   *prometheus.Desc
	nvmeMediaErrorsDesc      *prometheus.Desc
	nvmeUnsafeShutdownsDesc  *prometheus.Desc
	nvmeErrorLogEntriesDesc  *prometheus.Desc
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	if config.ExtraArgs == nil {
		config.ExtraArgs = ConfigDefaults.ExtraArgs
	}

	return &Collector{config: *config}
}

func NewWithFlags(app *kingpin.Application) *Collector {
	c := &Collector{config: ConfigDefaults}
	c.config.ExtraArgs = make([]string, 0)

	app.Flag(
		"collector.smart.smartctl-path",
		"Path to the smartctl executable (from smartmontools).",
	).Default(ConfigDefaults.SmartctlPath).StringVar(&c.config.SmartctlPath)

	app.Flag(
		"collector.smart.extra-args",
		"Comma-separated list of extra arguments to pass to smartctl when collecting SMART data.",
	).Default(strings.Join(ConfigDefaults.ExtraArgs, ",")).StringsVar(&c.config.ExtraArgs)

	return c
}

func (c *Collector) GetName() string {
	return Name
}

func (c *Collector) Close() error {
	return nil
}

func (c *Collector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))

	if c.config.SmartctlPath == "" {
		c.config.SmartctlPath = ConfigDefaults.SmartctlPath
	}

	smartctlPath, err := resolveSmartctlPath(c.config.SmartctlPath)
	if err != nil {
		return err
	}

	c.smartctlPath = smartctlPath

	c.infoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "info"),
		"SMART device information reported by smartctl",
		[]string{"model", "model_family", "serial_number", "firmware_version", "protocol", "type"},
		nil,
	)
	c.healthStatusDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "health_status"),
		"SMART overall-health self-assessment test status",
		[]string{"model", "serial_number", "status"},
		nil,
	)
	c.temperatureDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "temperature_celsius"),
		"Current device temperature in Celsius",
		[]string{"model", "serial_number"},
		nil,
	)
	c.powerOnHoursDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "power_on_hours"),
		"Total number of hours the device has been powered on",
		[]string{"model", "serial_number"},
		nil,
	)
	c.powerCyclesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "power_cycles"),
		"Total number of power cycles",
		[]string{"model", "serial_number"},
		nil,
	)
	c.reallocatedSectorsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "reallocated_sectors_total"),
		"Number of reallocated sectors (ATA SMART attribute 5)",
		[]string{"model", "serial_number"},
		nil,
	)
	c.pendingSectorsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "pending_sectors_total"),
		"Number of pending sectors awaiting reallocation (ATA SMART attribute 197)",
		[]string{"model", "serial_number"},
		nil,
	)
	c.offlineUncorrectableDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "offline_uncorrectable_sectors_total"),
		"Number of offline uncorrectable sectors (ATA SMART attribute 198)",
		[]string{"model", "serial_number"},
		nil,
	)
	c.nvmeDataUnitsReadDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "nvme_data_units_read_total"),
		"Number of NVMe data units read",
		[]string{"model", "serial_number"},
		nil,
	)
	c.nvmeDataUnitsWrittenDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "nvme_data_units_written_total"),
		"Number of NVMe data units written",
		[]string{"model", "serial_number"},
		nil,
	)
	c.nvmePercentageUsedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "nvme_percentage_used"),
		"NVMe percentage used (wear indicator)",
		[]string{"model", "serial_number"},
		nil,
	)
	c.nvmeMediaErrorsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "nvme_media_errors_total"),
		"NVMe media errors",
		[]string{"model", "serial_number"},
		nil,
	)
	c.nvmeUnsafeShutdownsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "nvme_unsafe_shutdowns_total"),
		"NVMe unsafe shutdowns",
		[]string{"model", "serial_number"},
		nil,
	)
	c.nvmeErrorLogEntriesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "nvme_error_log_entries_total"),
		"NVMe error log entries",
		[]string{"model", "serial_number"},
		nil,
	)

	return nil
}

func resolveSmartctlPath(path string) (string, error) {
	if path == "" {
		path = ConfigDefaults.SmartctlPath
	}

	if filepath.IsAbs(path) {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("failed to find smartctl executable at %q: %w", path, err)
		}

		return path, nil
	}

	smartctlPath, err := exec.LookPath(path)
	if err == nil {
		return smartctlPath, nil
	}

	exePath, exeErr := os.Executable()
	if exeErr != nil {
		return "", fmt.Errorf("failed to find smartctl executable %q: %w", path, err)
	}

	candidates := []string{
		filepath.Join(filepath.Dir(exePath), path),
		filepath.Join(os.Getenv("ProgramFiles"), "smartmontools", "bin", "smartctl.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "smartmontools", "bin", "smartctl.exe"),
		filepath.Join(string(os.Getenv("SystemDrive")), "smartmontools", "bin", "smartctl.exe"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "smartmontools", "bin", "smartctl.exe"),
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("failed to find smartctl executable %q (searched PATH, exporter directory, and standard install paths): %w", path, err)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	var scan smartctlScan
	if err := c.smartctlJSON([]string{"--scan-open", "-j"}, &scan); err != nil {
		return err
	}

	if len(scan.Devices) == 0 {
		return errors.New("smartctl scan returned no devices")
	}

	for _, device := range scan.Devices {
		var output smartctlOutput
		args := []string{"-a", "-j"}
		if device.Type != "" {
			args = append(args, "-d", device.Type)
		}
		for _, arg := range c.config.ExtraArgs {
			if arg == "" {
				continue
			}
			args = append(args, arg)
		}
		args = append(args, device.Name)

		if err := c.smartctlJSON(args, &output); err != nil {
			return err
		}

		modelName := strings.TrimSpace(output.ModelName)
		if modelName == "" {
			modelName = "unknown"
		}
		serialNumber := strings.TrimSpace(output.SerialNumber)
		if serialNumber == "" {
			serialNumber = "unknown"
		}

		ch <- prometheus.MustNewConstMetric(
			c.infoDesc,
			prometheus.GaugeValue,
			1,
			modelName,
			output.ModelFamily,
			serialNumber,
			output.FirmwareVersion,
			output.Device.Protocol,
			output.Device.Type,
		)

		status := smartStatusUnknown
		if output.SmartStatus != nil {
			if output.SmartStatus.Passed {
				status = smartStatusPassed
			} else {
				status = smartStatusFailed
			}
		}

		for _, candidate := range smartStatusValues {
			value := 0.0
			if candidate == status {
				value = 1.0
			}

			ch <- prometheus.MustNewConstMetric(
				c.healthStatusDesc,
				prometheus.GaugeValue,
				value,
				modelName,
				serialNumber,
				candidate,
			)
		}

		if temp := smartTemperature(&output); temp != nil {
			ch <- prometheus.MustNewConstMetric(
				c.temperatureDesc,
				prometheus.GaugeValue,
				*temp,
				modelName,
				serialNumber,
			)
		}

		if hours := smartPowerOnHours(&output); hours != nil {
			ch <- prometheus.MustNewConstMetric(
				c.powerOnHoursDesc,
				prometheus.GaugeValue,
				*hours,
				modelName,
				serialNumber,
			)
		}

		if cycles := smartPowerCycles(&output); cycles != nil {
			ch <- prometheus.MustNewConstMetric(
				c.powerCyclesDesc,
				prometheus.GaugeValue,
				*cycles,
				modelName,
				serialNumber,
			)
		}

		if value := ataAttributeValue(output.AtaSmartAttributes, ataReallocatedSectors); value != nil {
			ch <- prometheus.MustNewConstMetric(
				c.reallocatedSectorsDesc,
				prometheus.GaugeValue,
				*value,
				modelName,
				serialNumber,
			)
		}

		if value := ataAttributeValue(output.AtaSmartAttributes, ataPendingSectors); value != nil {
			ch <- prometheus.MustNewConstMetric(
				c.pendingSectorsDesc,
				prometheus.GaugeValue,
				*value,
				modelName,
				serialNumber,
			)
		}

		if value := ataAttributeValue(output.AtaSmartAttributes, ataOfflineUncorrectable); value != nil {
			ch <- prometheus.MustNewConstMetric(
				c.offlineUncorrectableDesc,
				prometheus.GaugeValue,
				*value,
				modelName,
				serialNumber,
			)
		}

		if output.NVMeSmartHealthLog != nil {
			if value := output.NVMeSmartHealthLog.DataUnitsRead; value != nil {
				ch <- prometheus.MustNewConstMetric(
					c.nvmeDataUnitsReadDesc,
					prometheus.GaugeValue,
					*value,
					modelName,
					serialNumber,
				)
			}
			if value := output.NVMeSmartHealthLog.DataUnitsWritten; value != nil {
				ch <- prometheus.MustNewConstMetric(
					c.nvmeDataUnitsWrittenDesc,
					prometheus.GaugeValue,
					*value,
					modelName,
					serialNumber,
				)
			}
			if value := output.NVMeSmartHealthLog.PercentageUsed; value != nil {
				ch <- prometheus.MustNewConstMetric(
					c.nvmePercentageUsedDesc,
					prometheus.GaugeValue,
					*value,
					modelName,
					serialNumber,
				)
			}
			if value := output.NVMeSmartHealthLog.MediaErrors; value != nil {
				ch <- prometheus.MustNewConstMetric(
					c.nvmeMediaErrorsDesc,
					prometheus.GaugeValue,
					*value,
					modelName,
					serialNumber,
				)
			}
			if value := output.NVMeSmartHealthLog.UnsafeShutdowns; value != nil {
				ch <- prometheus.MustNewConstMetric(
					c.nvmeUnsafeShutdownsDesc,
					prometheus.GaugeValue,
					*value,
					modelName,
					serialNumber,
				)
			}
			if value := output.NVMeSmartHealthLog.NumErrLogEntries; value != nil {
				ch <- prometheus.MustNewConstMetric(
					c.nvmeErrorLogEntriesDesc,
					prometheus.GaugeValue,
					*value,
					modelName,
					serialNumber,
				)
			}
		}
	}

	return nil
}

type smartctlScan struct {
	Devices []smartctlDevice `json:"devices"`
}

type smartctlDevice struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
}

type smartctlOutput struct {
	Device             smartctlDevice          `json:"device"`
	ModelName          string                  `json:"model_name"`
	ModelFamily        string                  `json:"model_family"`
	SerialNumber       string                  `json:"serial_number"`
	FirmwareVersion    string                  `json:"firmware_version"`
	SmartStatus        *smartctlHealthStatus   `json:"smart_status"`
	Temperature        *smartctlTemperature    `json:"temperature"`
	PowerOnTime        *smartctlPowerOnTime    `json:"power_on_time"`
	PowerCycleCount    *float64                `json:"power_cycle_count"`
	AtaSmartAttributes *smartctlAtaAttributes  `json:"ata_smart_attributes"`
	NVMeSmartHealthLog *smartctlNvmeHealthInfo `json:"nvme_smart_health_information_log"`
}

type smartctlHealthStatus struct {
	Passed bool `json:"passed"`
}

type smartctlTemperature struct {
	Current *float64 `json:"current"`
}

type smartctlPowerOnTime struct {
	Hours *float64 `json:"hours"`
}

type smartctlAtaAttributes struct {
	Table []smartctlAtaAttribute `json:"table"`
}

type smartctlAtaAttribute struct {
	ID  int                     `json:"id"`
	Raw smartctlAtaAttributeRaw `json:"raw"`
}

type smartctlAtaAttributeRaw struct {
	Value *float64 `json:"value"`
}

type smartctlNvmeHealthInfo struct {
	Temperature      *float64 `json:"temperature"`
	PowerOnHours     *float64 `json:"power_on_hours"`
	PowerCycles      *float64 `json:"power_cycles"`
	DataUnitsRead    *float64 `json:"data_units_read"`
	DataUnitsWritten *float64 `json:"data_units_written"`
	PercentageUsed   *float64 `json:"percentage_used"`
	MediaErrors      *float64 `json:"media_errors"`
	UnsafeShutdowns  *float64 `json:"unsafe_shutdowns"`
	NumErrLogEntries *float64 `json:"num_err_log_entries"`
}

const (
	ataReallocatedSectors   = 5
	ataPendingSectors       = 197
	ataOfflineUncorrectable = 198
)

const (
	smartStatusPassed  = "passed"
	smartStatusFailed  = "failed"
	smartStatusUnknown = "unknown"
)

//nolint:gochecknoglobals
var smartStatusValues = []string{
	smartStatusPassed,
	smartStatusFailed,
	smartStatusUnknown,
}

func ataAttributeValue(attrs *smartctlAtaAttributes, id int) *float64 {
	if attrs == nil {
		return nil
	}

	for _, entry := range attrs.Table {
		if entry.ID == id {
			return entry.Raw.Value
		}
	}

	return nil
}

func smartTemperature(output *smartctlOutput) *float64 {
	if output.Temperature != nil && output.Temperature.Current != nil {
		return output.Temperature.Current
	}

	if output.NVMeSmartHealthLog != nil && output.NVMeSmartHealthLog.Temperature != nil {
		value := *output.NVMeSmartHealthLog.Temperature
		if value > 200 {
			value -= 273
		}
		return &value
	}

	return nil
}

func smartPowerOnHours(output *smartctlOutput) *float64 {
	if output.PowerOnTime != nil && output.PowerOnTime.Hours != nil {
		return output.PowerOnTime.Hours
	}

	if output.NVMeSmartHealthLog != nil {
		return output.NVMeSmartHealthLog.PowerOnHours
	}

	return nil
}

func smartPowerCycles(output *smartctlOutput) *float64 {
	if output.PowerCycleCount != nil {
		return output.PowerCycleCount
	}

	if output.NVMeSmartHealthLog != nil {
		return output.NVMeSmartHealthLog.PowerCycles
	}

	return nil
}

func (c *Collector) smartctlJSON(args []string, dst any) error {
	output, err := c.runSmartctl(args)
	if err != nil {
		if jsonErr := json.Unmarshal(output, dst); jsonErr == nil {
			c.logger.Warn(
				"smartctl returned a non-zero exit code",
				slog.String("args", strings.Join(args, " ")),
				slog.String("error", err.Error()),
			)
			return nil
		}

		return fmt.Errorf("smartctl failed: %w: %s", err, strings.TrimSpace(string(output)))
	}

	if err := json.Unmarshal(output, dst); err != nil {
		return fmt.Errorf("failed to parse smartctl JSON: %w", err)
	}

	return nil
}

func (c *Collector) runSmartctl(args []string) ([]byte, error) {
	cmd := exec.Command(c.smartctlPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, err
	}

	return output, nil
}
