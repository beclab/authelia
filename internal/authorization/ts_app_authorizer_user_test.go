package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func TestIsCreatedUser(t *testing.T) {
	created := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "alice"},
		"status":   map[string]interface{}{"state": userStateCreated},
	}}
	pending := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "bob"},
		"status":   map[string]interface{}{"state": "Failed"},
	}}

	assert.True(t, isCreatedUser(created))
	assert.False(t, isCreatedUser(pending))
	assert.False(t, isCreatedUser("not-a-user"))
	assert.True(t, isCreatedUser(cache.DeletedFinalStateUnknown{Obj: created}))
	assert.False(t, isCreatedUser(cache.DeletedFinalStateUnknown{Obj: pending}))

	state, ok := createdUserState(created)
	assert.True(t, ok)
	assert.Equal(t, userStateCreated, state)

	state, ok = createdUserState(pending)
	assert.False(t, ok)
	assert.Equal(t, "Failed", state)
}
