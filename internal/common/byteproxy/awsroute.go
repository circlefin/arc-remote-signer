// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package byteproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	awsRouteMagic   = "ARSP"
	awsRouteVersion = byte(1)
	awsRoutePrefix  = len(awsRouteMagic) + 3
)

// AWSRoute identifies the AWS service and region selected by an enclave SDK
// client. It is sent before the untouched TLS or HTTP stream.
type AWSRoute struct {
	Service string
	Region  string
}

// WriteAWSRoute writes one bounded routing header to w.
func WriteAWSRoute(w io.Writer, route AWSRoute) error {
	if route.Service == "" || len(route.Service) > 255 {
		return errors.New("byteproxy: AWS route service must contain 1-255 bytes")
	}
	if route.Region == "" || len(route.Region) > 255 {
		return errors.New("byteproxy: AWS route region must contain 1-255 bytes")
	}
	header := make([]byte, 0, awsRoutePrefix+len(route.Service)+len(route.Region))
	header = append(header, awsRouteMagic...)
	header = append(header, awsRouteVersion, byte(len(route.Service)), byte(len(route.Region)))
	header = append(header, route.Service...)
	header = append(header, route.Region...)
	n, err := w.Write(header)
	if err != nil {
		return fmt.Errorf("byteproxy: write AWS route: %w", err)
	}
	if n != len(header) {
		return fmt.Errorf(
			"byteproxy: write AWS route: wrote %d of %d bytes: %w",
			n, len(header), io.ErrShortWrite,
		)
	}
	return nil
}

// ReadAWSRoute reads exactly one routing header from r and leaves the
// following TLS or HTTP bytes unread. On error, bytes already read from r are
// not restored.
func ReadAWSRoute(r io.Reader) (AWSRoute, error) {
	prefix := make([]byte, awsRoutePrefix)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return AWSRoute{}, fmt.Errorf("byteproxy: read AWS route prefix: %w", err)
	}
	if !bytes.Equal(prefix[:len(awsRouteMagic)], []byte(awsRouteMagic)) {
		return AWSRoute{}, errors.New("byteproxy: invalid magic in AWS route header")
	}
	if prefix[len(awsRouteMagic)] != awsRouteVersion {
		return AWSRoute{}, fmt.Errorf("byteproxy: unsupported AWS route version %d", prefix[len(awsRouteMagic)])
	}
	serviceLen := int(prefix[len(awsRouteMagic)+1])
	regionLen := int(prefix[len(awsRouteMagic)+2])
	if serviceLen == 0 || regionLen == 0 {
		return AWSRoute{}, errors.New("byteproxy: AWS route service and region must be non-empty")
	}
	payload := make([]byte, serviceLen+regionLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return AWSRoute{}, fmt.Errorf("byteproxy: read AWS route payload: %w", err)
	}
	return AWSRoute{
		Service: string(payload[:serviceLen]),
		Region:  string(payload[serviceLen:]),
	}, nil
}
