package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type metrics struct {
	requests         *prometheus.CounterVec
	providerDuration *prometheus.HistogramVec
}

func newMetrics(registry *prometheus.Registry) *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "acme_proxy_requests_total",
			Help: "API requests by action, client and result.",
		}, []string{"action", "client", "result"}),

		providerDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "acme_proxy_provider_duration_seconds",
			Help:    "Time spent in DNS provider calls.",
			Buckets: prometheus.DefBuckets,
		}, []string{"provider", "action"}),
	}

	registry.MustRegister(
		m.requests,
		m.providerDuration,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return m
}

// observeRequest records the outcome of a request. result is "ok" or the error
// code that was returned.
func (m *metrics) observeRequest(action, client, result string) {
	if client == "" {
		client = "unknown"
	}

	m.requests.WithLabelValues(action, client, result).Inc()
}

func (m *metrics) observeProvider(provider, action string, seconds float64) {
	m.providerDuration.WithLabelValues(provider, action).Observe(seconds)
}
