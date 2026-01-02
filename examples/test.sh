#!/bin/bash

set -e

echo "Building goflow2-aggregator..."
cargo build --release

echo ""
echo "Starting goflow2-aggregator in background..."
cat examples/sample_flow.json | ./target/release/goflow2-aggregator &
PID=$!

echo "Waiting for metrics server to start..."
sleep 2

echo ""
echo "Fetching metrics from http://localhost:9090/metrics..."
curl -s http://localhost:9090/metrics | grep -E "^goflow_"

echo ""
echo "Stopping goflow2-aggregator (PID: $PID)..."
kill $PID 2>/dev/null || true

echo ""
echo "Test completed successfully!"
