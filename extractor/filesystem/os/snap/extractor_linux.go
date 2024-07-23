// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

// Package snap extracts snap packages
package snap

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"

	"github.com/go-yaml/yaml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/snap"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

type snap struct {
	Name          string   `yaml:"name"`
	Version       string   `yaml:"version"`
	Grade         string   `yaml:"grade"`
	Type          string   `yaml:"type"`
	Architectures []string `yaml:"architectures"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
		Stats:            nil,
	}
}

// Extractor extracts snap apps.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a SNAP extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches snap.yaml file pattern.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	// the yaml file is found in snap/<app>/<revision>/meta/snap.yaml
	filePathRegex := regexp.MustCompile(`^snap/[^/]*/[^/]*/meta/snap.yaml$`)
	if match := filePathRegex.FindString(path); match == "" {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts snap info from snap.yaml file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventory, err := e.extractFromInput(ctx, input)
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory, err
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	m, err := osrelease.GetOSRelease(input.ScanRoot)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	snap := snap{}
	dec := yaml.NewDecoder(input.Reader)
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("failed to yaml decode %q: %v", input.Path, err)
	}

	if snap.Name == "" {
		return nil, fmt.Errorf("missing snap name from %q", input.Path)
	}

	if snap.Version == "" {
		return nil, fmt.Errorf("missing snap version from %q", input.Path)
	}

	inventory := &extractor.Inventory{
		Name:    snap.Name,
		Version: snap.Version,
		Metadata: &Metadata{
			Name:              snap.Name,
			Version:           snap.Version,
			Grade:             snap.Grade,
			Type:              snap.Type,
			Architectures:     snap.Architectures,
			OSID:              m["ID"],
			OSVersionCodename: m["VERSION_CODENAME"],
			OSVersionID:       m["VERSION_ID"],
		},
		Locations: []string{input.Path},
	}
	return []*extractor.Inventory{inventory}, nil
}

// ToPURL is not applicable for SNAP as is not a part of the PURL spec.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) { return nil, nil }

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
