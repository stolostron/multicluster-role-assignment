/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

func FindDifference(sliceA, sliceB []string) []string {
	diff := []string{}
	// Create a map to quickly check for elements in sliceB
	bMap := make(map[string]bool)
	for _, item := range sliceB {
		bMap[item] = true
	}

	// Iterate through sliceA and add elements not found in bMap to diff
	for _, item := range sliceA {
		if _, found := bMap[item]; !found {
			diff = append(diff, item)
		}
	}
	return diff
}
