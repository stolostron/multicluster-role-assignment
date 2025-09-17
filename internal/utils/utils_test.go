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

import (
	"reflect"
	"sort"
	"testing"
)

func TestFindDifference(t *testing.T) {
	tests := []struct {
		name     string
		sliceA   []string
		sliceB   []string
		expected []string
	}{
		{
			name:     "Basic difference - some elements unique to A",
			sliceA:   []string{"a", "b", "c", "d"},
			sliceB:   []string{"b", "d", "e", "f"},
			expected: []string{"a", "c"},
		},
		{
			name:     "No difference - all elements in A are also in B",
			sliceA:   []string{"a", "b", "c"},
			sliceB:   []string{"a", "b", "c", "d", "e"},
			expected: []string{},
		},
		{
			name:     "Complete difference - no common elements",
			sliceA:   []string{"a", "b", "c"},
			sliceB:   []string{"x", "y", "z"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Empty sliceA - should return empty",
			sliceA:   []string{},
			sliceB:   []string{"a", "b", "c"},
			expected: []string{},
		},
		{
			name:     "Empty sliceB - should return all of sliceA",
			sliceA:   []string{"a", "b", "c"},
			sliceB:   []string{},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Both slices empty - should return empty",
			sliceA:   []string{},
			sliceB:   []string{},
			expected: []string{},
		},
		{
			name:     "Nil sliceA - should return empty",
			sliceA:   nil,
			sliceB:   []string{"a", "b", "c"},
			expected: []string{},
		},
		{
			name:     "Nil sliceB - should return all of sliceA",
			sliceA:   []string{"a", "b", "c"},
			sliceB:   nil,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Both slices nil - should return empty",
			sliceA:   nil,
			sliceB:   nil,
			expected: []string{},
		},
		{
			name:     "Duplicates in sliceA - should preserve all duplicates",
			sliceA:   []string{"a", "b", "a", "c", "b"},
			sliceB:   []string{"d", "e"},
			expected: []string{"a", "b", "a", "c", "b"},
		},
		{
			name:     "Duplicates in sliceB - should not affect result",
			sliceA:   []string{"a", "b", "c"},
			sliceB:   []string{"b", "b", "b", "d"},
			expected: []string{"a", "c"},
		},
		{
			name:     "Duplicates in both slices",
			sliceA:   []string{"a", "b", "a", "c"},
			sliceB:   []string{"b", "b", "d"},
			expected: []string{"a", "a", "c"},
		},
		{
			name:     "Single element slices - element in both",
			sliceA:   []string{"a"},
			sliceB:   []string{"a"},
			expected: []string{},
		},
		{
			name:     "Single element slices - different elements",
			sliceA:   []string{"a"},
			sliceB:   []string{"b"},
			expected: []string{"a"},
		},
		{
			name:     "Case sensitive comparison",
			sliceA:   []string{"a", "A", "b"},
			sliceB:   []string{"a", "c"},
			expected: []string{"A", "b"},
		},
		{
			name:     "Empty strings",
			sliceA:   []string{"", "a", ""},
			sliceB:   []string{"", "b"},
			expected: []string{"a"},
		},
		{
			name:     "Whitespace strings",
			sliceA:   []string{" ", "  ", "a"},
			sliceB:   []string{" ", "b"},
			expected: []string{"  ", "a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindDifference(tt.sliceA, tt.sliceB)

			// For nil expected, treat as empty slice for comparison
			expected := tt.expected
			if expected == nil {
				expected = []string{}
			}

			// Sort both slices for comparison since order might not matter
			// But preserve original order by comparing unsorted first if lengths match
			if len(result) == len(expected) {
				// Try direct comparison first (preserves order)
				if reflect.DeepEqual(result, expected) {
					return // Test passed
				}
			}

			// If direct comparison failed or lengths differ, sort and compare
			sortedResult := make([]string, len(result))
			copy(sortedResult, result)
			sort.Strings(sortedResult)

			sortedExpected := make([]string, len(expected))
			copy(sortedExpected, expected)
			sort.Strings(sortedExpected)

			if !reflect.DeepEqual(sortedResult, sortedExpected) {
				t.Errorf("FindDifference() = %v, expected %v", result, expected)
			}
		})
	}
}

func TestFindDifferencePreservesOrder(t *testing.T) {
	// Test that the function preserves the order of elements from sliceA
	sliceA := []string{"z", "a", "y", "b", "x"}
	sliceB := []string{"a", "b"}
	expected := []string{"z", "y", "x"}

	result := FindDifference(sliceA, sliceB)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("FindDifference() should preserve order from sliceA. Got %v, expected %v", result, expected)
	}
}

func TestFindDifferenceWithDuplicatesPreservesAll(t *testing.T) {
	// Test that duplicates in sliceA are preserved in the result
	sliceA := []string{"a", "b", "a", "c", "a"}
	sliceB := []string{"b", "d"}
	expected := []string{"a", "a", "c", "a"}

	result := FindDifference(sliceA, sliceB)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("FindDifference() should preserve all duplicates from sliceA. Got %v, expected %v", result, expected)
	}
}
