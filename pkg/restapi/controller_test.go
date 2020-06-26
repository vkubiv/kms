/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

func TestController_New(t *testing.T) {
	controller := New(mockstore.NewMockStoreProvider())
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	controller := New(mockstore.NewMockStoreProvider())
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, "/kms/createKeystore", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())
}
