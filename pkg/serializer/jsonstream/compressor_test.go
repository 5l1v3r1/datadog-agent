// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

//+build zlib

package jsonstream

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/serializer/marshaler"
)

var (
	maxPayloadSizeDefault = config.Datadog.GetInt("serializer_max_payload_size")
)

type dummyMarshaller struct {
	items               []string
	header              string
	footer              string
	itemIndexInPayloads []int
}

func resetDefaults() {
	config.Datadog.SetDefault("serializer_max_payload_size", maxPayloadSizeDefault)
}

func (p *dummyMarshaller) Initialize() error { return nil }

func (d *dummyMarshaller) WriteHeader(stream *jsoniter.Stream) error {
	_, err := stream.Write([]byte(d.header))
	return err
}

func (d *dummyMarshaller) Len() int {
	return len(d.items)
}

func (d *dummyMarshaller) WriteItem(stream *jsoniter.Stream, i int, itemIndexInPayload int) error {
	if i < 0 || i > d.Len()-1 {
		return errors.New("out of range")
	}
	d.itemIndexInPayloads = append(d.itemIndexInPayloads, itemIndexInPayload)
	_, err := stream.Write([]byte(d.items[i]))
	return err
}

func (d *dummyMarshaller) DescribeItem(i int) string {
	if i < 0 || i > d.Len()-1 {
		return "out of range"
	}
	return d.items[i]
}

func (d *dummyMarshaller) WriteFooter(stream *jsoniter.Stream) error {
	_, err := stream.Write([]byte(d.footer))
	return err
}

func (p *dummyMarshaller) AddJSONSeparatoraAutomatically() bool { return true }
func (p *dummyMarshaller) WriteLastFooter(stream *jsoniter.Stream, itemWrittenCount int) error {
	return p.WriteFooter(stream)
}

func (d *dummyMarshaller) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (d *dummyMarshaller) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (d *dummyMarshaller) SplitPayload(int) ([]marshaler.Marshaler, error) {
	return nil, fmt.Errorf("not implemented")
}

func decompressPayload(payload []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	dst, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func payloadToString(payload []byte) string {
	p, err := decompressPayload(payload)
	if err != nil {
		return err.Error()
	}
	return string(p)
}

func TestCompressorSimple(t *testing.T) {
	footer := []byte("]}")
	c, err := newCompressor(&bytes.Buffer{}, &bytes.Buffer{}, []byte("{["), footer, true)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		c.addItem([]byte("A"))
	}

	p, err := c.close(footer)
	require.NoError(t, err)
	require.Equal(t, "{[A,A,A,A,A]}", payloadToString(p))
}

func TestOnePayloadSimple(t *testing.T) {
	m := &dummyMarshaller{
		items:  []string{"A", "B", "C"},
		header: "{[",
		footer: "]}",
	}

	builder := NewPayloadBuilder()
	payloads, err := builder.Build(m)
	require.NoError(t, err)
	require.Len(t, payloads, 1)

	require.Equal(t, "{[A,B,C]}", payloadToString(*payloads[0]))
}

func TestMaxCompressedSizePayload(t *testing.T) {
	m := &dummyMarshaller{
		items:  []string{"A", "B", "C"},
		header: "{[",
		footer: "]}",
	}
	config.Datadog.SetDefault("serializer_max_payload_size", 22)
	defer resetDefaults()

	builder := NewPayloadBuilder()
	payloads, err := builder.Build(m)
	require.NoError(t, err)
	require.Len(t, payloads, 1)

	require.Equal(t, "{[A,B,C]}", payloadToString(*payloads[0]))
}

func TestTwoPayload(t *testing.T) {
	m := &dummyMarshaller{
		items:  []string{"A", "B", "C", "D", "E", "F"},
		header: "{[",
		footer: "]}",
	}
	config.Datadog.SetDefault("serializer_max_payload_size", 22)
	defer resetDefaults()

	builder := NewPayloadBuilder()
	payloads, err := builder.Build(m)
	require.NoError(t, err)
	require.Len(t, payloads, 2)

	require.Equal(t, "{[A,B,C]}", payloadToString(*payloads[0]))
	require.Equal(t, "{[D,E,F]}", payloadToString(*payloads[1]))
	require.Equal(t, []int{0, 1, 2, 3, 0, 1, 2}, m.itemIndexInPayloads)
}
