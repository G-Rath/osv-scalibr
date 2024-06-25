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

package dpkg

// Metadata holds parsing information for a dpkg package.
type Metadata struct {
	PackageName       string
	Status            string
	SourceName        string
	SourceVersion     string
	PackageVersion    string
	OSID              string
	OSVersionCodename string
	OSVersionID       string
	Maintainer        string
	Architecture      string
}
