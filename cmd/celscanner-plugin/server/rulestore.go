package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/hashicorp/go-hclog"
	"gopkg.in/yaml.v3"
)

// RuleStore manages YAML-based storage of CEL rules
type RuleStore struct {
	mu       sync.RWMutex
	basePath string
	rules    map[string]*StoredRule
}

// StoredRule represents a rule with metadata stored in YAML
type StoredRule struct {
	ID          string                   `yaml:"id"`
	Name        string                   `yaml:"name"`
	Description string                   `yaml:"description"`
	Expression  string                   `yaml:"expression"`
	Inputs      []map[string]interface{} `yaml:"inputs"`
	Tags        []string                 `yaml:"tags"`
	Category    string                   `yaml:"category"`
	Severity    string                   `yaml:"severity"`
	Extensions  map[string]interface{}   `yaml:"extensions,omitempty"`
	CreatedAt   time.Time                `yaml:"created_at"`
	UpdatedAt   time.Time                `yaml:"updated_at"`
	CreatedBy   string                   `yaml:"created_by"`
	CheckID     string                   `yaml:"check_id,omitempty"`
}

// GetCELInputs converts the stored inputs map to celscanner.Input interfaces
func (r *StoredRule) GetCELInputs() ([]celscanner.Input, error) {
	var inputs []celscanner.Input
	for _, input := range r.Inputs {
		hclog.Default().Debug("Input", "input", input)

		// Parse the input based on its type
		name, ok := input["name"].(string)
		if !ok {
			return nil, fmt.Errorf("input missing name field")
		}

		// Check for different input types
		if kubeConfig, exists := input["kubernetes"]; exists {
			if kubeMap, ok := kubeConfig.(map[string]interface{}); ok {
				version, _ := kubeMap["version"].(string)
				if version == "" {
					version = "v1"
				}

				resourceType, _ := kubeMap["resourceType"].(string)
				if resourceType == "" {
					resourceType, _ = kubeMap["resource"].(string)
				}

				namespace, _ := kubeMap["namespace"].(string)
				apiGroup, _ := kubeMap["apiGroup"].(string)
				resourceName, _ := kubeMap["resourceName"].(string)

				celInput := celscanner.NewKubernetesInput(name, apiGroup, version, resourceType, namespace, resourceName)
				inputs = append(inputs, celInput)
			}
		} else if fileConfig, exists := input["file"]; exists {
			if fileMap, ok := fileConfig.(map[string]interface{}); ok {
				path, _ := fileMap["path"].(string)
				format, _ := fileMap["format"].(string)
				if format == "" {
					format = "text"
				}

				recursive, _ := fileMap["recursive"].(bool)
				checkPermissions, _ := fileMap["checkPermissions"].(bool)

				celInput := celscanner.NewFileInput(name, path, format, recursive, checkPermissions)
				inputs = append(inputs, celInput)
			}
		} else if systemConfig, exists := input["system"]; exists {
			if systemMap, ok := systemConfig.(map[string]interface{}); ok {
				command, _ := systemMap["command"].(string)
				service, _ := systemMap["service"].(string)

				var args []string
				if argsInterface, exists := systemMap["args"]; exists {
					if argsList, ok := argsInterface.([]interface{}); ok {
						for _, arg := range argsList {
							if argStr, ok := arg.(string); ok {
								args = append(args, argStr)
							}
						}
					}
				}

				celInput := celscanner.NewSystemInput(name, command, service, args)
				inputs = append(inputs, celInput)
			}
		} else if httpConfig, exists := input["http"]; exists {
			if httpMap, ok := httpConfig.(map[string]interface{}); ok {
				url, _ := httpMap["url"].(string)
				method, _ := httpMap["method"].(string)
				if method == "" {
					method = "GET"
				}

				var headers map[string]string
				if headersInterface, exists := httpMap["headers"]; exists {
					if headersMap, ok := headersInterface.(map[string]interface{}); ok {
						headers = make(map[string]string)
						for k, v := range headersMap {
							if vStr, ok := v.(string); ok {
								headers[k] = vStr
							}
						}
					}
				}
				var body []byte
				if bodyInterface, exists := httpMap["body"]; exists {
					if bodyBytes, ok := bodyInterface.([]byte); ok {
						body = bodyBytes
					}
				}

				celInput := celscanner.NewHTTPInput(name, url, method, headers, body)
				inputs = append(inputs, celInput)
			}
		} else {
			return nil, fmt.Errorf("unknown input type for input: %s", name)
		}
	}
	return inputs, nil
}

// NewRuleStore creates a new YAML-based rule store
func NewRuleStore(basePath string) (*RuleStore, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rule store directory: %w", err)
	}

	store := &RuleStore{
		basePath: basePath,
		rules:    make(map[string]*StoredRule),
	}

	// Load existing rules
	if err := store.loadRules(); err != nil {
		return nil, fmt.Errorf("failed to load existing rules: %w", err)
	}

	return store, nil
}

// loadRules loads all YAML rule files from the base directory
func (s *RuleStore) loadRules() error {
	files, err := ioutil.ReadDir(s.basePath)
	if err != nil {
		return err
	}

	hclog.Default().Info("Loading rules from YAML store", "path", s.basePath, "file_count", len(files))

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			filePath := filepath.Join(s.basePath, file.Name())
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				hclog.Default().Error("Failed to read rule file", "file", filePath, "error", err)
				continue
			}
			hclog.Default().Debug("rule", "data", string(data))

			var rule StoredRule
			if err := yaml.Unmarshal(data, &rule); err != nil {
				hclog.Default().Error("Failed to unmarshal rule", "file", filePath, "error", err)
				continue
			}

			s.rules[rule.ID] = &rule
			hclog.Default().Debug("Loaded rule", "id", rule.ID, "name", rule.Name, "expression", rule.Expression, "inputs", rule.Inputs)
		}
	}

	hclog.Default().Info("Loaded rules", "total", len(s.rules))
	return nil
}

// Save stores a rule to YAML file
func (s *RuleStore) Save(rule *StoredRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	rule.UpdatedAt = time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = rule.UpdatedAt
	}

	// Marshal to YAML with nice formatting
	data, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	filename := filepath.Join(s.basePath, rule.ID+".yaml")
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %w", err)
	}

	s.rules[rule.ID] = rule
	hclog.Default().Info("Saved rule", "id", rule.ID, "file", filename)

	return nil
}

// Get retrieves a rule by ID
func (s *RuleStore) Get(id string) (*StoredRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rule, exists := s.rules[id]
	if !exists {
		return nil, fmt.Errorf("rule not found: %s", id)
	}

	return rule, nil
}

// List returns all rules with optional filtering
func (s *RuleStore) List(filter map[string]string) []*StoredRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*StoredRule

	for _, rule := range s.rules {
		if s.matchesFilter(rule, filter) {
			results = append(results, rule)
		}
	}

	return results
}

// matchesFilter checks if a rule matches the given filter criteria
func (s *RuleStore) matchesFilter(rule *StoredRule, filter map[string]string) bool {
	if len(filter) == 0 {
		return true
	}

	for key, value := range filter {
		switch key {
		case "category":
			if rule.Category != value {
				return false
			}
		case "severity":
			if rule.Severity != value {
				return false
			}
		case "check_id":
			if rule.CheckID != value {
				return false
			}
		case "tag":
			found := false
			for _, tag := range rule.Tags {
				if tag == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// Delete removes a rule from storage
func (s *RuleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[id]; !exists {
		return fmt.Errorf("rule not found: %s", id)
	}

	filename := filepath.Join(s.basePath, id+".yaml")
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("failed to delete rule file: %w", err)
	}

	delete(s.rules, id)
	hclog.Default().Info("Deleted rule", "id", id)

	return nil
}

// ConvertToCelRule converts a StoredRule to celscanner.CelRule
func (s *RuleStore) ConvertToCelRule(stored *StoredRule) (celscanner.CelRule, error) {
	builder := celscanner.NewRuleBuilder(stored.ID).
		WithName(stored.Name).
		WithDescription(stored.Description).
		SetExpression(stored.Expression)

	hclog.Default().Debug("Converting rule to CEL rule", "rule", stored)
	// Convert and add inputs
	celInputs, err := stored.GetCELInputs()
	hclog.Default().Debug("CEL inputs", "inputs", celInputs)
	if err != nil {
		hclog.Default().Warn("Failed to convert inputs for rule", "id", stored.ID, "error", err)
	}
	for _, input := range celInputs {
		hclog.Default().Debug("Adding input", "input", input)
		builder.WithInput(input)
	}
	// Add tags as extension
	if len(stored.Tags) > 0 {
		builder.WithExtension("tags", stored.Tags)
	}

	// Add category and severity as extensions
	if stored.Category != "" {
		builder.WithExtension("category", stored.Category)
	}
	if stored.Severity != "" {
		builder.WithExtension("severity", stored.Severity)
	}
	if stored.CheckID != "" {
		builder.WithExtension("check_id", stored.CheckID)
	}
	if stored.Category != "" {
		builder.WithExtension("category", stored.Category)
	}
	if stored.Severity != "" {
		builder.WithExtension("severity", stored.Severity)
	}
	if !stored.CreatedAt.IsZero() {
		builder.WithExtension("created_at", stored.CreatedAt.Format(time.RFC3339))
	}
	if !stored.UpdatedAt.IsZero() {
		builder.WithExtension("updated_at", stored.UpdatedAt.Format(time.RFC3339))
	}
	if stored.CreatedBy != "" {
		builder.WithExtension("created_by", stored.CreatedBy)
	}

	// Add other extensions
	for key, value := range stored.Extensions {
		builder.WithExtension(key, value)
	}

	return builder.Build()
}

// ExportRules exports rules to a single YAML file
func (s *RuleStore) ExportRules(ruleIDs []string, outputPath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rulesToExport []*StoredRule

	if len(ruleIDs) > 0 {
		// Export specific rules
		for _, id := range ruleIDs {
			if rule, exists := s.rules[id]; exists {
				rulesToExport = append(rulesToExport, rule)
			}
		}
	} else {
		// Export all rules
		for _, rule := range s.rules {
			rulesToExport = append(rulesToExport, rule)
		}
	}

	// Create export structure
	export := struct {
		Version  string        `yaml:"version"`
		Rules    []*StoredRule `yaml:"rules"`
		Exported time.Time     `yaml:"exported"`
	}{
		Version:  "1.0",
		Rules:    rulesToExport,
		Exported: time.Now(),
	}

	data, err := yaml.Marshal(export)
	if err != nil {
		return fmt.Errorf("failed to marshal rules for export: %w", err)
	}

	if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	hclog.Default().Info("Exported rules", "count", len(rulesToExport), "file", outputPath)
	return nil
}

// ImportRules imports rules from a YAML file
func (s *RuleStore) ImportRules(inputPath string, overwrite bool) error {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	// Try to unmarshal as export format first
	var export struct {
		Version string        `yaml:"version"`
		Rules   []*StoredRule `yaml:"rules"`
	}

	if err := yaml.Unmarshal(data, &export); err == nil && len(export.Rules) > 0 {
		// Import from export format
		for _, rule := range export.Rules {
			if !overwrite {
				if _, exists := s.rules[rule.ID]; exists {
					hclog.Default().Warn("Skipping existing rule", "id", rule.ID)
					continue
				}
			}
			if err := s.Save(rule); err != nil {
				hclog.Default().Error("Failed to import rule", "id", rule.ID, "error", err)
			}
		}
		return nil
	}

	// Try to unmarshal as array of rules
	var rules []*StoredRule
	if err := yaml.Unmarshal(data, &rules); err == nil {
		for _, rule := range rules {
			if !overwrite {
				if _, exists := s.rules[rule.ID]; exists {
					hclog.Default().Warn("Skipping existing rule", "id", rule.ID)
					continue
				}
			}
			if err := s.Save(rule); err != nil {
				hclog.Default().Error("Failed to import rule", "id", rule.ID, "error", err)
			}
		}
		return nil
	}

	// Try single rule
	var rule StoredRule
	if err := yaml.Unmarshal(data, &rule); err == nil {
		if !overwrite {
			if _, exists := s.rules[rule.ID]; exists {
				return fmt.Errorf("rule already exists: %s", rule.ID)
			}
		}
		return s.Save(&rule)
	}

	return fmt.Errorf("unable to parse import file format")
}
