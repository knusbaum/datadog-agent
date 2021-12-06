// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package tcp

import (
	"expvar"
	"net"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Destination is responsible for shipping logs to a remote server over TCP.
type Destination struct {
	sync.Mutex
	prefixer            *prefixer
	delimiter           Delimiter
	connManager         *ConnectionManager
	destinationsContext *client.DestinationsContext
	conn                net.Conn
	connCreationTime    time.Time
	shouldRetry         bool
	isRetrying          bool
}

// NewDestination returns a new destination.
func NewDestination(endpoint config.Endpoint, useProto bool, destinationsContext *client.DestinationsContext, shouldRetry bool) *Destination {
	prefix := endpoint.APIKey + string(' ')
	metrics.DestinationLogsDropped.Set(endpoint.Host, &expvar.Int{})
	return &Destination{
		prefixer:            newPrefixer(prefix),
		delimiter:           NewDelimiter(useProto),
		connManager:         NewConnectionManager(endpoint),
		destinationsContext: destinationsContext,
		shouldRetry:         shouldRetry,
		isRetrying:          false,
	}
}

// Start reads from the input, transforms a message into a frame and sends it to a remote server,
// TODO: return retry channel and close it
func (d *Destination) Start(input chan *message.Payload, output chan *message.Payload) (stopChan chan struct{}) {
	stopChan = make(chan struct{})
	go func() {
		for payload := range input {
			d.sendAndRetry(payload, output)
		}
		d.Lock()
		d.isRetrying = false
		d.Unlock()
		stopChan <- struct{}{}
	}()
	return stopChan
}

// GetIsRetrying returns true if the destination is retrying
func (d *Destination) GetIsRetrying() bool {
	d.Lock()
	defer d.Unlock()
	return d.isRetrying
}

func (d *Destination) sendAndRetry(payload *message.Payload, output chan *message.Payload) {
	for {
		if d.conn == nil {
			var err error

			// We work only if we have a started destination context
			ctx := d.destinationsContext.Context()
			if d.conn, err = d.connManager.NewConnection(ctx); err != nil {
				// the connection manager is not meant to fail,
				// this can happen only when the context is cancelled.
				d.incrementErrors(true)
				return
			}
			d.connCreationTime = time.Now()
		}

		content := d.prefixer.apply(payload.Encoded)
		frame, err := d.delimiter.delimit(content)
		if err != nil {
			// the delimiter can fail when the payload can not be framed correctly.
			d.incrementErrors(true)
			return
		}

		_, err = d.conn.Write(frame)
		if err != nil {
			d.connManager.CloseConnection(d.conn)
			d.conn = nil

			if d.shouldRetry {
				d.Lock()
				d.isRetrying = true
				d.Unlock()
				d.incrementErrors(false)
				// TODO: report retries
				// retry (will try to open a new connection)
				continue
			} else {
				d.incrementErrors(true)
			}
		}

		d.Lock()
		d.isRetrying = false
		d.Unlock()

		metrics.LogsSent.Add(1)
		metrics.TlmLogsSent.Inc()
		metrics.BytesSent.Add(int64(len(payload.Encoded)))
		metrics.TlmBytesSent.Add(float64(len(payload.Encoded)))
		metrics.EncodedBytesSent.Add(int64(len(payload.Encoded)))
		metrics.TlmEncodedBytesSent.Add(float64(len(payload.Encoded)))
		output <- payload

		if d.connManager.ShouldReset(d.connCreationTime) {
			log.Debug("Resetting TCP connection")
			d.connManager.CloseConnection(d.conn)
			d.conn = nil
		}
		return
	}
}

func (d *Destination) incrementErrors(drop bool) {
	if drop {
		host := d.connManager.endpoint.Host
		metrics.DestinationLogsDropped.Add(host, 1)
		metrics.TlmLogsDropped.Inc(host)
	}
	metrics.DestinationErrors.Add(1)
	metrics.TlmDestinationErrors.Inc()
}
