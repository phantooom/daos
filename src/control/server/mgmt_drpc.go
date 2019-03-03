//
// (C) Copyright 2018-2019 Intel Corporation.
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
// GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
// The Government's rights to use, modify, reproduce, release, perform, display,
// or disclose this software are subject to the terms of the Apache License as
// provided in Contract No. 8F-30005.
// Any reproduction of computer software, computer software documentation, or
// portions thereof marked with this legend must also reproduce the markings.
//

package main

// #cgo CFLAGS: -I../../include
// #include <daos/drpc_modules.h>
import "C"
import (
	"fmt"

	pb "github.com/daos-stack/daos/src/control/common/proto/mgmt"
	"github.com/daos-stack/daos/src/control/drpc"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

const (
	mgmtModuleID   int32 = C.DRPC_MODULE_MGMT
	methodKillRank int32 = C.DRPC_METHOD_MGMT_KILL_RANK
)

// MgmtModule is the management drpc module struct
type MgmtModule struct{}

// InitModule is empty for this module
func (m *MgmtModule) InitModule(state drpc.ModuleState) {}

// ID will return Mgmt module ID
func (m *MgmtModule) ID() int32 {
	return mgmtModuleID
}

// MakeCall connects creates and sends message through the MgmtModule
//func (m *MgmtModule) MakeCall(client *drpc.Client, method int32, body []byte) ([]byte, error) {

// HandleCall is the handler for calls to the MgmtModule
func (m *MgmtModule) HandleCall(client *drpc.Client, method int32, body []byte) ([]byte, error) {
	return nil, errors.New("mgmt module handler is not implemented")
}

// callDrpcMethodWithMessage create a new drpc Call instance, open a
// drpc connection, send a message with the protobuf message marshalled
// in the body, and closes the connection. Returns unmarshalled response.
func (c *controlService) callDrpcMethodWithMessage(
	methodID int32, body proto.Message) (resp *pb.DaosResponse, err error) {

	drpcResp, err := makeDrpcCall(c.drpc, mgmtModuleID, methodID, body)
	if err != nil {
		fmt.Printf("%+v\n", err)
		return nil, errors.WithStack(err)
	}

	resp = &pb.DaosResponse{}
	err = proto.Unmarshal(drpcResp.Body, resp)
	if err != nil {
		return nil, fmt.Errorf("invalid dRPC response body: %v", err)
	}

	return
}
