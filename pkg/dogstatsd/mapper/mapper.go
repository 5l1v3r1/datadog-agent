// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2019 Datadog, Inc.

// Mapping feature is inspired by https://github.com/prometheus/statsd_exporter

package mapper

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	allowedGlobMatchPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_*.]+$`)
)

const (
	matchTypeGlob  = "glob"
	matchTypeRegex = "regex"
)

// MetricMapper contains mappings and cache instance
type MetricMapper struct {
	Mappings []MetricMapping
	cache    *mapperCache
}

// MetricMapping represent one mapping rule
type MetricMapping struct {
	Match     string            `mapstructure:"match"`
	MatchType string            `mapstructure:"match_type"`
	Name      string            `mapstructure:"name"`
	Tags      map[string]string `mapstructure:"tags"`
	regex     *regexp.Regexp
}

// NewMetricMapper creates, validates, prepares a new MetricMapper
func NewMetricMapper(configMappings []MetricMapping, cacheSize int) (MetricMapper, error) {
	var mappings []MetricMapping
	for i := range configMappings {
		currentMapping := configMappings[i]
		if currentMapping.MatchType == "" {
			currentMapping.MatchType = matchTypeGlob
		}
		if currentMapping.MatchType != matchTypeGlob && currentMapping.MatchType != matchTypeRegex {
			return MetricMapper{}, fmt.Errorf("mapping num %d: invalid match type, must be `glob` or `regex`", i)
		}
		if currentMapping.Name == "" {
			return MetricMapper{}, fmt.Errorf("mapping num %d: name is required", i)
		}
		if currentMapping.Match == "" {
			return MetricMapper{}, fmt.Errorf("mapping num %d: match is required", i)
		}
		err := currentMapping.prepare()
		if err != nil {
			return MetricMapper{}, err
		}
		mappings = append(mappings, currentMapping)
	}
	cache, err := newMapperCache(cacheSize)
	if err != nil {
		return MetricMapper{}, err
	}
	return MetricMapper{Mappings: mappings, cache: cache}, nil
}

// prepare compiles the match patterns into regexes
func (m *MetricMapping) prepare() error {
	metricRe := m.Match
	if m.MatchType == matchTypeGlob {
		if !allowedGlobMatchPattern.MatchString(m.Match) {
			return fmt.Errorf("invalid glob match pattern `%s`, it does not match allowed match regex `%s`", m.Match, allowedGlobMatchPattern)
		}
		if strings.Contains(m.Match, "**") {
			return fmt.Errorf("invalid glob match pattern `%s`, it should not contain consecutive `*`", m.Match)
		}
		metricRe = strings.Replace(metricRe, ".", "\\.", -1)
		metricRe = strings.Replace(metricRe, "*", "([^.]*)", -1)
	}
	regex, err := regexp.Compile("^" + metricRe + "$")
	if err != nil {
		return fmt.Errorf("invalid match `%s`. cannot compile regex: %v", m.Match, err)
	}
	m.regex = regex
	return nil
}

// GetMapping returns:
// - name: the mapped expanded name
// - tags: the tags extracted from the metric name and expanded
// - matched: weather we found a match or not
func (m *MetricMapper) GetMapping(metricName string) (string, []string, bool) {
	result, cached := m.cache.get(metricName)
	if cached {
		return result.Name, result.Tags, result.Matched
	}
	for _, mapping := range m.Mappings {
		matches := mapping.regex.FindStringSubmatchIndex(metricName)
		if len(matches) == 0 {
			continue
		}

		name := string(mapping.regex.ExpandString(
			[]byte{},
			mapping.Name,
			metricName,
			matches,
		))

		var tags []string
		for tagKey, tagValueExpr := range mapping.Tags {
			tagValue := string(mapping.regex.ExpandString([]byte{}, tagValueExpr, metricName, matches))
			tags = append(tags, tagKey+":"+tagValue)
		}

		m.cache.addMatch(metricName, name, tags)
		return name, tags, true
	}
	m.cache.addMiss(metricName)
	return "", nil, false
}