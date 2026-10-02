// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vsockproxy

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenNitroParentVsock_UsesNitroParentCID(t *testing.T) {
	const port uint32 = 10316
	wantErr := errors.New("listener stopped")
	var gotCID uint32
	var gotPort uint32
	listen := func(cid, port uint32) (net.Listener, error) {
		gotCID = cid
		gotPort = port
		return nil, wantErr
	}

	_, err := listenNitroParentVsock(port, listen)

	require.ErrorIs(t, err, wantErr)
	require.Equal(t, uint32(3), gotCID)
	require.Equal(t, port, gotPort)
}
