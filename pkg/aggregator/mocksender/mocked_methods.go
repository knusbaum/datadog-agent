// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package mocksender

import (
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/serializer"
)

//Rate adds a rate type to the mock calls.
func (m *MockSender) Rate(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//Count adds a count type to the mock calls.
func (m *MockSender) Count(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//MonotonicCount adds a monotonic count type to the mock calls.
func (m *MockSender) MonotonicCount(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//MonotonicCountWithFlushFirstValue adds a monotonic count type to the mock calls with flushFirstValue parameter
func (m *MockSender) MonotonicCountWithFlushFirstValue(metric string, value float64, hostname string, tags []string, flushFirstValue bool) {
	m.Called(metric, value, hostname, tags, flushFirstValue)
}

//Counter adds a counter type to the mock calls.
func (m *MockSender) Counter(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//Histogram adds a histogram type to the mock calls.
func (m *MockSender) Histogram(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//Historate adds a historate type to the mock calls.
func (m *MockSender) Historate(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//Gauge adds a gauge type to the mock calls.
func (m *MockSender) Gauge(metric string, value float64, hostname string, tags []string) {
	m.Called(metric, value, hostname, tags)
}

//ServiceCheck enables the service check mock call.
func (m *MockSender) ServiceCheck(checkName string, status metrics.ServiceCheckStatus, hostname string, tags []string, message string) {
	m.Called(checkName, status, hostname, tags, message)
}

//DisableDefaultHostname enables the hostname mock call.
func (m *MockSender) DisableDefaultHostname(d bool) {
	m.Called(d)
}

//Event enables the event mock call.
func (m *MockSender) Event(e metrics.Event) {
	m.Called(e)
}

//EventPlatformEvent enables the event platform event mock call.
func (m *MockSender) EventPlatformEvent(rawEvent string, eventType string) {
	m.Called(rawEvent, eventType)
}

//HistogramBucket enables the histogram bucket mock call.
func (m *MockSender) HistogramBucket(metric string, value int64, lowerBound, upperBound float64, monotonic bool, hostname string, tags []string, flushFirstValue bool) {
	m.Called(metric, value, lowerBound, upperBound, monotonic, hostname, tags, flushFirstValue)
}

//Commit enables the commit mock call.
func (m *MockSender) Commit() {
	m.Called()
}

//SetCheckCustomTags enables the set of check custom tags mock call.
func (m *MockSender) SetCheckCustomTags(tags []string) {
	m.Called(tags)
}

//SetCheckService enables the setting of check service mock call.
func (m *MockSender) SetCheckService(service string) {
	m.Called(service)
}

//FinalizeCheckServiceTag enables the sending of check service tag mock call.
func (m *MockSender) FinalizeCheckServiceTag() {
	m.Called()
}

//GetSenderStats enables the get metric stats mock call.
func (m *MockSender) GetSenderStats() check.SenderStats {
	m.Called()
	return check.NewSenderStats()
}

// OrchestratorMetadata submit orchestrator metadata messages
func (m *MockSender) OrchestratorMetadata(msgs []serializer.ProcessMessageBody, clusterID string, nodeType int) {
	m.Called(msgs, clusterID, nodeType)
}

// ContainerLifecycleEvent submit container life cycle messages
func (m *MockSender) ContainerLifecycleEvent(msgs []serializer.ContainerLifecycleMessage) {
	m.Called(msgs)
}

// OrchestratorManifest submit orchestrator manifest messages
func (m *MockSender) OrchestratorManifest(msgs []serializer.ManifestMessage, clusterName string, clusterID string) {
	m.Called(msgs, clusterName, clusterID)
}
