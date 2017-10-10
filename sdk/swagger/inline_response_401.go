/*
 * Oathkeeper
 *
 * Oathkeeper
 *
 * OpenAPI spec version: Latest
 * Contact: hi@ory.am
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

package swagger

type InlineResponse401 struct {
	Code int64 `json:"code,omitempty"`

	Details []map[string]interface{} `json:"details,omitempty"`

	Message string `json:"message,omitempty"`

	Reason string `json:"reason,omitempty"`

	Request string `json:"request,omitempty"`

	Status string `json:"status,omitempty"`
}
