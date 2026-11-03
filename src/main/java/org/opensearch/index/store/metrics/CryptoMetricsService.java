/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import java.io.Closeable;
import java.util.function.Supplier;

import org.opensearch.telemetry.metrics.Counter;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.telemetry.metrics.tags.Tags;

/**
 * Registry for crypto operations metrics and tracing.
 * Provides centralized access to telemetry data collection for encryption/decryption operations.
 */
public class CryptoMetricsService {
    private static volatile CryptoMetricsService instance;
    private final MetricsRegistry metricsRegistry;
    private final Counter errorCounter;
    private final Counter indexErrorCounter;

    // Metric names
    private static final String ERROR_COUNTER_NAME = "crypto.error.total";
    private static final String INDEX_ERROR_COUNTER_NAME = "crypto.index.error.total";

    // Metric descriptions
    private static final String ERROR_COUNTER_DESC = "Total crypto operation errors, by error type";
    private static final String INDEX_ERROR_COUNTER_DESC = "Crypto errors that affect one index, by error type and index. "
        + "One series per index: collectors that bill per series can drop crypto.index.* by name";

    // Units
    private static final String COUNT_UNIT = "count";

    // Tag names
    private static final String ERROR_TYPE_TAG = "error_type";
    private static final String INDEX_NAME = "index_name";

    // Error message
    private static final String NOT_INITIALIZED_ERROR = "CryptoMetricsRegistry not initialized.";

    /**
     * Private constructor for singleton pattern.
     * @param metricsRegistry the metrics registry for collecting metrics
     */
    private CryptoMetricsService(MetricsRegistry metricsRegistry) {
        this.metricsRegistry = metricsRegistry;
        this.errorCounter = createCounter(ERROR_COUNTER_NAME, ERROR_COUNTER_DESC, COUNT_UNIT);
        this.indexErrorCounter = createCounter(INDEX_ERROR_COUNTER_NAME, INDEX_ERROR_COUNTER_DESC, COUNT_UNIT);
    }

    /**
     * Initializes the singleton instance.
     * @param metricsRegistry the metrics registry for collecting metrics
     */
    public static synchronized void initialize(MetricsRegistry metricsRegistry) {
        if (instance == null) {
            instance = new CryptoMetricsService(metricsRegistry);
        }
    }

    /**
     * Gets the singleton instance.
     * @return the CryptoMetricsRegistry instance
     * @throws IllegalStateException if not initialized
     */
    public static CryptoMetricsService getInstance() {
        if (instance == null) {
            throw new IllegalStateException(NOT_INITIALIZED_ERROR);
        }
        return instance;
    }

    /**
     * Registers a gauge that the telemetry exporter reads when it collects, so the value is always current
     * and nothing runs on a timer here. Close the returned handle to unregister it.
     *
     * @param name metric name
     * @param description metric description
     * @param unit metric unit
     * @param value reads the current value; must be cheap and must not throw
     * @return handle that unregisters the gauge; a no-op when metrics are disabled
     */
    public Closeable registerGauge(String name, String description, String unit, Supplier<Double> value) {
        if (metricsRegistry == null) {
            return () -> {};
        }
        return metricsRegistry.createGauge(name, description, unit, value, Tags.EMPTY);
    }

    /**
     * Counts an error in {@code crypto.error.total}, tagged by error type only.
     * @param errorType the type of error
     */
    public void recordError(ErrorType errorType) {
        if (errorCounter != null) {
            errorCounter.add(1.0, Tags.create().addTag(ERROR_TYPE_TAG, errorType.getValue()));
        }
    }

    /**
     * Counts an error in {@code crypto.error.total} and, for error types that affect a single index
     * ({@link ErrorType#isIndexLevel()}), also in {@code crypto.index.error.total} tagged with the index name.
     * The node-level counter stays bounded by the number of error types; the per-index one is separate so
     * a collector can drop it by name.
     * @param errorType the type of error
     * @param indexName the index name
     */
    public void recordError(ErrorType errorType, String indexName) {
        recordError(errorType);
        if (indexErrorCounter != null && indexName != null && errorType.isIndexLevel()) {
            indexErrorCounter.add(1.0, Tags.create().addTag(ERROR_TYPE_TAG, errorType.getValue()).addTag(INDEX_NAME, indexName));
        }
    }

    /**
     * {@link #recordError(ErrorType)} on the instance, or nothing if metrics are not initialized
     * (unit tests, or before the plugin starts). For call sites on read paths that must never fail
     * because of metrics.
     * @param errorType the type of error
     */
    public static void count(ErrorType errorType) {
        CryptoMetricsService service = instance;
        if (service != null) {
            service.recordError(errorType);
        }
    }

    /**
     * {@link #recordError(ErrorType, String)} on the instance, or nothing if metrics are not initialized.
     * @param errorType the type of error
     * @param indexName the index name
     */
    public static void count(ErrorType errorType, String indexName) {
        CryptoMetricsService service = instance;
        if (service != null) {
            service.recordError(errorType, indexName);
        }
    }

    // Private helper methods
    private Counter createCounter(String name, String description, String unit) {
        return metricsRegistry != null ? metricsRegistry.createCounter(name, description, unit) : null;
    }

}
