//
// Copyright 2021 Outfox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package jwtsecrets

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
	"time"
)

func getTestBackend(t *testing.T) (*backend, *logical.Storage) {

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.BackendUUID = uuid.New().String()

	b, err := createBackend(config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.clock = &fakeClock{time.Unix(0, 0)}
	b.idGen = &fakeIDGenerator{0}

	_ = b.clearConfig(context.Background(), config.StorageView)

	return b, &config.StorageView
}
