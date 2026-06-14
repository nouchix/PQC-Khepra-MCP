// Schema Enforcement - Polymorphic Schema Learning Engine
// "The Papyrus of Thoth Records All Forms"
//
// This implements the self-learning API contract system inspired by
// SouHimBou.AI's PolymorphicSchemaEngine. It learns valid request/response
// patterns and detects deviations that may indicate attacks.
package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"sync"
	"time"
)

// SchemaEngine implements polymorphic schema learning and enforcement
type SchemaEngine struct {
	config *SchemaConfig

	// Learned schemas per endpoint
	schemas   map[string]*EndpointSchema
	schemasMu sync.RWMutex

	// Schema evolution tracking
	pendingEvolutions []SchemaEvolution

	// Learning state
	learningStarted time.Time
	sampleCount     int64
}

// EndpointSchema represents the learned schema for an endpoint
type EndpointSchema struct {
	Endpoint    string    `json:"endpoint"`
	Method      string    `json:"method"`
	Version     int       `json:"version"`
	LearnedAt   time.Time `json:"learned_at"`
	LastUpdated time.Time `json:"last_updated"`
	SampleCount int64     `json:"sample_count"`

	// Request schema
	Request *MessageSchema `json:"request"`

	// Response schema
	Response *MessageSchema `json:"response"`

	// Validation rules
	Rules []ValidationRule `json:"rules"`

	// Statistics for anomaly detection
	Stats EndpointStats `json:"stats"`
}

// MessageSchema represents the structure of a request or response body
type MessageSchema struct {
	ContentType string                 `json:"content_type"`
	Fields      map[string]*FieldSchema `json:"fields"`
	Required    []string               `json:"required"`
	MaxDepth    int                    `json:"max_depth"`
	MaxSize     int64                  `json:"max_size"`
}

// FieldSchema represents a single field in the schema
type FieldSchema struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "string", "number", "boolean", "array", "object", "null"
	Format      string                 `json:"format,omitempty"` // "email", "uri", "date-time", "uuid", etc.
	Pattern     string                 `json:"pattern,omitempty"` // Regex pattern for strings
	MinLength   *int                   `json:"min_length,omitempty"`
	MaxLength   *int                   `json:"max_length,omitempty"`
	Minimum     *float64               `json:"minimum,omitempty"`
	Maximum     *float64               `json:"maximum,omitempty"`
	Enum        []interface{}          `json:"enum,omitempty"`
	Items       *FieldSchema           `json:"items,omitempty"` // For arrays
	Properties  map[string]*FieldSchema `json:"properties,omitempty"` // For objects
	Nullable    bool                   `json:"nullable"`
	Frequency   float64                `json:"frequency"` // How often this field appears (0-1)
}

// ValidationRule defines a custom validation rule
type ValidationRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // "regex", "range", "enum", "custom"
	Field       string `json:"field"`
	Value       string `json:"value"`
	Severity    string `json:"severity"` // "block", "warn", "log"
}

// EndpointStats tracks statistics for anomaly detection
type EndpointStats struct {
	AvgRequestSize  float64 `json:"avg_request_size"`
	StdRequestSize  float64 `json:"std_request_size"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	StdResponseTime float64 `json:"std_response_time_ms"`
	SuccessRate     float64 `json:"success_rate"`
	FieldFrequencies map[string]float64 `json:"field_frequencies"`
}

// SchemaEvolution tracks proposed changes to schemas
type SchemaEvolution struct {
	Endpoint    string                 `json:"endpoint"`
	ChangeType  string                 `json:"change_type"` // "new_field", "type_change", "removed_field"
	Field       string                 `json:"field"`
	OldValue    interface{}            `json:"old_value,omitempty"`
	NewValue    interface{}            `json:"new_value"`
	Sample      map[string]interface{} `json:"sample"`
	DetectedAt  time.Time              `json:"detected_at"`
	Approved    bool                   `json:"approved"`
	ApprovedBy  string                 `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time             `json:"approved_at,omitempty"`
}

// SchemaValidationResult contains the result of schema validation
type SchemaValidationResult struct {
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors"`
	Warnings    []string `json:"warnings"`
	AnomalyScore float64 `json:"anomaly_score"`
	Evolution   *SchemaEvolution `json:"evolution,omitempty"`
}

// NewSchemaEngine creates a new schema enforcement engine
func NewSchemaEngine(cfg *SchemaConfig) *SchemaEngine {
	engine := &SchemaEngine{
		config:  cfg,
		schemas: make(map[string]*EndpointSchema),
	}

	if cfg.LearningEnabled {
		engine.learningStarted = time.Now()
		log.Printf("[SCHEMA] Learning mode enabled for %v", cfg.LearningDuration)
	}

	log.Printf("[SCHEMA] Engine initialized - Learning[%v] StrictMode[%v] AutoEvolve[%v]",
		cfg.LearningEnabled, cfg.StrictMode, cfg.AutoEvolve)

	return engine
}

// ValidateRequest validates a request against the learned schema
func (se *SchemaEngine) ValidateRequest(endpoint, method string, body []byte, contentType string) *SchemaValidationResult {
	key := se.schemaKey(endpoint, method)

	se.schemasMu.RLock()
	schema, exists := se.schemas[key]
	se.schemasMu.RUnlock()

	// If in learning mode, learn from request
	if se.config.LearningEnabled && time.Since(se.learningStarted) < se.config.LearningDuration {
		se.learnFromRequest(endpoint, method, body, contentType)
		return &SchemaValidationResult{Valid: true}
	}

	// No schema learned yet
	if !exists || schema.Request == nil {
		if se.config.StrictMode {
			return &SchemaValidationResult{
				Valid:  false,
				Errors: []string{"no schema exists for endpoint"},
			}
		}
		return &SchemaValidationResult{Valid: true, Warnings: []string{"no schema to validate against"}}
	}

	// Parse and validate
	return se.validateAgainstSchema(body, contentType, schema.Request)
}

// learnFromRequest learns schema from a request
func (se *SchemaEngine) learnFromRequest(endpoint, method string, body []byte, contentType string) {
	if len(body) == 0 {
		return
	}

	key := se.schemaKey(endpoint, method)

	se.schemasMu.Lock()
	defer se.schemasMu.Unlock()

	schema, exists := se.schemas[key]
	if !exists {
		schema = &EndpointSchema{
			Endpoint:  endpoint,
			Method:    method,
			Version:   1,
			LearnedAt: time.Now(),
			Request: &MessageSchema{
				ContentType: contentType,
				Fields:      make(map[string]*FieldSchema),
			},
			Stats: EndpointStats{
				FieldFrequencies: make(map[string]float64),
			},
		}
		se.schemas[key] = schema
	}

	// Parse JSON body
	if contentType == "application/json" || contentType == "" {
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return
		}

		se.learnFields(schema.Request.Fields, data, "", &schema.Stats.FieldFrequencies)
	}

	schema.SampleCount++
	schema.LastUpdated = time.Now()
	se.sampleCount++
}

// learnFields recursively learns field schemas from data
func (se *SchemaEngine) learnFields(fields map[string]*FieldSchema, data map[string]interface{}, prefix string, frequencies *map[string]float64) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		existing, exists := fields[key]
		if !exists {
			existing = &FieldSchema{
				Name:      key,
				Frequency: 1.0,
			}
			fields[key] = existing
		}

		// Update frequency
		if *frequencies != nil {
			(*frequencies)[fullKey]++
		}

		// Infer type
		se.inferType(existing, value)

		// Recurse for objects
		if obj, ok := value.(map[string]interface{}); ok {
			if existing.Properties == nil {
				existing.Properties = make(map[string]*FieldSchema)
			}
			se.learnFields(existing.Properties, obj, fullKey, frequencies)
		}

		// Learn array item type
		if arr, ok := value.([]interface{}); ok && len(arr) > 0 {
			if existing.Items == nil {
				existing.Items = &FieldSchema{Name: "items"}
			}
			se.inferType(existing.Items, arr[0])
		}
	}
}

// inferType infers the JSON schema type from a value
func (se *SchemaEngine) inferType(field *FieldSchema, value interface{}) {
	if value == nil {
		field.Nullable = true
		return
	}

	switch v := value.(type) {
	case string:
		field.Type = "string"
		// Try to detect format
		if field.Format == "" {
			field.Format = se.detectStringFormat(v)
		}
		// Update length constraints
		length := len(v)
		if field.MinLength == nil || length < *field.MinLength {
			field.MinLength = &length
		}
		if field.MaxLength == nil || length > *field.MaxLength {
			field.MaxLength = &length
		}

	case float64:
		field.Type = "number"
		if field.Minimum == nil || v < *field.Minimum {
			field.Minimum = &v
		}
		if field.Maximum == nil || v > *field.Maximum {
			field.Maximum = &v
		}

	case bool:
		field.Type = "boolean"

	case []interface{}:
		field.Type = "array"

	case map[string]interface{}:
		field.Type = "object"
	}
}

// detectStringFormat tries to detect common string formats
func (se *SchemaEngine) detectStringFormat(s string) string {
	// Email
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, s); matched {
		return "email"
	}

	// UUID
	if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`, s); matched {
		return "uuid"
	}

	// ISO Date-time
	if matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`, s); matched {
		return "date-time"
	}

	// Date
	if matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, s); matched {
		return "date"
	}

	// URI/URL
	if matched, _ := regexp.MatchString(`^https?://`, s); matched {
		return "uri"
	}

	// IPv4
	if matched, _ := regexp.MatchString(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, s); matched {
		return "ipv4"
	}

	return ""
}

// validateAgainstSchema validates data against a learned schema
func (se *SchemaEngine) validateAgainstSchema(body []byte, contentType string, schema *MessageSchema) *SchemaValidationResult {
	result := &SchemaValidationResult{
		Valid:  true,
		Errors: []string{},
		Warnings: []string{},
	}

	// Check content type
	if schema.ContentType != "" && contentType != schema.ContentType {
		result.Warnings = append(result.Warnings, fmt.Sprintf("unexpected content type: %s", contentType))
	}

	// Check size
	if schema.MaxSize > 0 && int64(len(body)) > schema.MaxSize {
		result.Valid = false
		result.Errors = append(result.Errors, "request body exceeds maximum size")
		return result
	}

	// Parse JSON
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid JSON: %v", err))
		return result
	}

	// Check required fields
	for _, required := range schema.Required {
		if _, exists := data[required]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("missing required field: %s", required))
		}
	}

	// Validate each field
	anomalyScore := 0.0
	for key, value := range data {
		fieldSchema, exists := schema.Fields[key]
		if !exists {
			// Unknown field
			if se.config.StrictMode {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("unknown field: %s", key))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("unknown field: %s", key))
				anomalyScore += 0.2
			}

			// Track as potential evolution
			if se.config.AutoEvolve {
				se.trackEvolution("new_field", schema.ContentType, key, nil, value)
			}
			continue
		}

		// Validate field
		if err := se.validateField(fieldSchema, value); err != nil {
			if se.config.StrictMode {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("field %s: %v", key, err))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("field %s: %v", key, err))
				anomalyScore += 0.3
			}
		}
	}

	result.AnomalyScore = anomalyScore
	return result
}

// validateField validates a single field against its schema
func (se *SchemaEngine) validateField(schema *FieldSchema, value interface{}) error {
	// Handle null
	if value == nil {
		if !schema.Nullable {
			return fmt.Errorf("null value not allowed")
		}
		return nil
	}

	// Check type
	actualType := se.getJSONType(value)
	if actualType != schema.Type && schema.Type != "" {
		return fmt.Errorf("expected type %s, got %s", schema.Type, actualType)
	}

	// Type-specific validation
	switch v := value.(type) {
	case string:
		// Length validation
		if schema.MinLength != nil && len(v) < *schema.MinLength {
			return fmt.Errorf("string length %d below minimum %d", len(v), *schema.MinLength)
		}
		if schema.MaxLength != nil && len(v) > *schema.MaxLength {
			return fmt.Errorf("string length %d exceeds maximum %d", len(v), *schema.MaxLength)
		}

		// Pattern validation
		if schema.Pattern != "" {
			matched, err := regexp.MatchString(schema.Pattern, v)
			if err != nil || !matched {
				return fmt.Errorf("value does not match pattern")
			}
		}

		// Enum validation
		if len(schema.Enum) > 0 {
			found := false
			for _, e := range schema.Enum {
				if e == v {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("value not in allowed enum")
			}
		}

	case float64:
		if schema.Minimum != nil && v < *schema.Minimum {
			return fmt.Errorf("value %f below minimum %f", v, *schema.Minimum)
		}
		if schema.Maximum != nil && v > *schema.Maximum {
			return fmt.Errorf("value %f exceeds maximum %f", v, *schema.Maximum)
		}

	case []interface{}:
		// Validate array items
		if schema.Items != nil {
			for i, item := range v {
				if err := se.validateField(schema.Items, item); err != nil {
					return fmt.Errorf("array item %d: %v", i, err)
				}
			}
		}

	case map[string]interface{}:
		// Validate object properties
		if schema.Properties != nil {
			for propKey, propValue := range v {
				if propSchema, exists := schema.Properties[propKey]; exists {
					if err := se.validateField(propSchema, propValue); err != nil {
						return fmt.Errorf("property %s: %v", propKey, err)
					}
				}
			}
		}
	}

	return nil
}

// getJSONType returns the JSON type string for a value
func (se *SchemaEngine) getJSONType(value interface{}) string {
	if value == nil {
		return "null"
	}

	t := reflect.TypeOf(value)
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Float64, reflect.Float32, reflect.Int, reflect.Int64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice:
		return "array"
	case reflect.Map:
		return "object"
	default:
		return "unknown"
	}
}

// trackEvolution tracks a schema evolution for approval
func (se *SchemaEngine) trackEvolution(changeType, endpoint, field string, oldValue, newValue interface{}) {
	evolution := SchemaEvolution{
		Endpoint:   endpoint,
		ChangeType: changeType,
		Field:      field,
		OldValue:   oldValue,
		NewValue:   newValue,
		DetectedAt: time.Now(),
	}

	se.schemasMu.Lock()
	se.pendingEvolutions = append(se.pendingEvolutions, evolution)
	se.schemasMu.Unlock()

	log.Printf("[SCHEMA] Evolution detected: %s.%s (%s)", endpoint, field, changeType)

	// Notify webhook if configured
	if se.config.NotifyWebhook != "" {
		go se.notifyEvolution(evolution)
	}
}

// notifyEvolution posts a schema evolution event to the configured webhook URL.
func (se *SchemaEngine) notifyEvolution(evolution SchemaEvolution) {
	body, err := json.Marshal(evolution)
	if err != nil {
		log.Printf("[SCHEMA] Failed to marshal evolution for webhook: %v", err)
		return
	}

	resp, err := http.Post(se.config.NotifyWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[SCHEMA] Webhook POST failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("[SCHEMA] Webhook returned non-2xx status: %d", resp.StatusCode)
	}
}

// GetPendingEvolutions returns pending schema evolutions
func (se *SchemaEngine) GetPendingEvolutions() []SchemaEvolution {
	se.schemasMu.RLock()
	defer se.schemasMu.RUnlock()

	result := make([]SchemaEvolution, len(se.pendingEvolutions))
	copy(result, se.pendingEvolutions)
	return result
}

// ApproveEvolution approves a schema evolution
func (se *SchemaEngine) ApproveEvolution(index int, approver string) error {
	se.schemasMu.Lock()
	defer se.schemasMu.Unlock()

	if index < 0 || index >= len(se.pendingEvolutions) {
		return fmt.Errorf("invalid evolution index")
	}

	evolution := &se.pendingEvolutions[index]
	evolution.Approved = true
	evolution.ApprovedBy = approver
	now := time.Now()
	evolution.ApprovedAt = &now

	// Apply evolution to schema
	se.applyEvolution(*evolution)

	log.Printf("[SCHEMA] Evolution approved: %s.%s by %s", evolution.Endpoint, evolution.Field, approver)
	return nil
}

// applyEvolution applies an approved evolution to the schema
func (se *SchemaEngine) applyEvolution(evolution SchemaEvolution) {
	key := evolution.Endpoint
	schema, exists := se.schemas[key]
	if !exists {
		return
	}

	switch evolution.ChangeType {
	case "new_field":
		if schema.Request != nil && schema.Request.Fields != nil {
			newField := &FieldSchema{Name: evolution.Field}
			se.inferType(newField, evolution.NewValue)
			schema.Request.Fields[evolution.Field] = newField
		}

	case "type_change":
		// Update field type

	case "removed_field":
		// Mark field as optional/deprecated
	}

	schema.Version++
	schema.LastUpdated = time.Now()
}

// GetSchema returns the learned schema for an endpoint
func (se *SchemaEngine) GetSchema(endpoint, method string) *EndpointSchema {
	key := se.schemaKey(endpoint, method)

	se.schemasMu.RLock()
	defer se.schemasMu.RUnlock()

	if schema, exists := se.schemas[key]; exists {
		return schema
	}
	return nil
}

// ExportSchemas exports all learned schemas
func (se *SchemaEngine) ExportSchemas() map[string]*EndpointSchema {
	se.schemasMu.RLock()
	defer se.schemasMu.RUnlock()

	result := make(map[string]*EndpointSchema)
	for k, v := range se.schemas {
		result[k] = v
	}
	return result
}

// ImportSchemas imports schemas from a registry
func (se *SchemaEngine) ImportSchemas(schemas map[string]*EndpointSchema) {
	se.schemasMu.Lock()
	defer se.schemasMu.Unlock()

	for k, v := range schemas {
		se.schemas[k] = v
	}

	log.Printf("[SCHEMA] Imported %d schemas from registry", len(schemas))
}

// schemaKey generates the key for schema lookup
func (se *SchemaEngine) schemaKey(endpoint, method string) string {
	return method + ":" + endpoint
}

// GetStats returns schema engine statistics
func (se *SchemaEngine) GetStats() map[string]interface{} {
	se.schemasMu.RLock()
	defer se.schemasMu.RUnlock()

	return map[string]interface{}{
		"schema_count":          len(se.schemas),
		"total_samples":         se.sampleCount,
		"pending_evolutions":    len(se.pendingEvolutions),
		"learning_enabled":      se.config.LearningEnabled,
		"learning_started":      se.learningStarted,
		"learning_remaining":    se.config.LearningDuration - time.Since(se.learningStarted),
	}
}
