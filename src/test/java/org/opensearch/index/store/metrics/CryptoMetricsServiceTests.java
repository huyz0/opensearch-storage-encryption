/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.Closeable;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.mockito.ArgumentCaptor;
import org.opensearch.telemetry.metrics.Counter;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.telemetry.metrics.tags.Tags;
import org.opensearch.test.OpenSearchTestCase;

public class CryptoMetricsServiceTests extends OpenSearchTestCase {

    private MetricsRegistry mockMetricsRegistry;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        resetSingleton();

        mockMetricsRegistry = mock(MetricsRegistry.class);

        when(mockMetricsRegistry.createCounter(any(), any(), any())).thenReturn(mock(Counter.class));
    }

    @After
    public void tearDown() throws Exception {
        resetSingleton();
        super.tearDown();
    }

    private void resetSingleton() throws Exception {
        Field instanceField = CryptoMetricsService.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
    }

    @SuppressWarnings("unchecked")
    public void testRegisterGaugeReadsSupplierAndUnregisters() throws Exception {
        Closeable handle = mock(Closeable.class);
        ArgumentCaptor<Supplier<Double>> value = ArgumentCaptor.forClass(Supplier.class);
        when(mockMetricsRegistry.createGauge(eq("crypto.test.gauge"), any(), eq("count"), value.capture(), eq(Tags.EMPTY)))
            .thenReturn(handle);
        CryptoMetricsService.initialize(mockMetricsRegistry);
        AtomicLong current = new AtomicLong(3);

        Closeable registered = CryptoMetricsService
            .getInstance()
            .registerGauge("crypto.test.gauge", "test", "count", () -> (double) current.get());
        assertEquals(3.0, value.getValue().get(), 0.0);
        current.set(7);
        assertEquals(7.0, value.getValue().get(), 0.0);

        registered.close();
        verify(handle).close();
    }

    public void testRegisterGaugeWithoutRegistryIsNoOp() throws Exception {
        CryptoMetricsService.initialize(null);
        CryptoMetricsService.getInstance().registerGauge("crypto.test.gauge", "test", "count", () -> 1.0).close();
    }

    public void testIndexLevelErrorCountsOnNodeAndIndexCounters() {
        Counter node = mock(Counter.class);
        Counter index = mock(Counter.class);
        when(mockMetricsRegistry.createCounter(eq("crypto.error.total"), any(), any())).thenReturn(node);
        when(mockMetricsRegistry.createCounter(eq("crypto.index.error.total"), any(), any())).thenReturn(index);
        CryptoMetricsService.initialize(mockMetricsRegistry);

        CryptoMetricsService.getInstance().recordError(ErrorType.KMS_KEY_ERROR, "logs-1");

        ArgumentCaptor<Tags> nodeTags = ArgumentCaptor.forClass(Tags.class);
        verify(node).add(eq(1.0), nodeTags.capture());
        assertEquals(Map.of("error_type", "kms_key_error"), nodeTags.getValue().getTagsMap());
        ArgumentCaptor<Tags> indexTags = ArgumentCaptor.forClass(Tags.class);
        verify(index).add(eq(1.0), indexTags.capture());
        assertEquals(Map.of("error_type", "kms_key_error", "index_name", "logs-1"), indexTags.getValue().getTagsMap());
    }

    public void testNodeLevelErrorSkipsIndexCounter() {
        Counter node = mock(Counter.class);
        Counter index = mock(Counter.class);
        when(mockMetricsRegistry.createCounter(eq("crypto.error.total"), any(), any())).thenReturn(node);
        when(mockMetricsRegistry.createCounter(eq("crypto.index.error.total"), any(), any())).thenReturn(index);
        CryptoMetricsService.initialize(mockMetricsRegistry);

        CryptoMetricsService.count(ErrorType.AUTH_FAILURE, "logs-1");
        CryptoMetricsService.count(ErrorType.POOL_EXHAUSTED);

        verify(node, times(2)).add(eq(1.0), any(Tags.class));
        verifyNoInteractions(index);
    }

    public void testCountIsNoOpWhenNotInitialized() {
        CryptoMetricsService.count(ErrorType.AUTH_FAILURE);
        CryptoMetricsService.count(ErrorType.KMS_KEY_ERROR, "logs-1");
        expectThrows(IllegalStateException.class, CryptoMetricsService::getInstance);
    }

    public void testOnlyKeyErrorsAreIndexLevel() {
        for (ErrorType type : ErrorType.values()) {
            boolean expected = type == ErrorType.KMS_KEY_ERROR || type == ErrorType.KMS_INDEX_BLOCKED;
            assertEquals(type.name(), expected, type.isIndexLevel());
        }
    }
}
