/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

public enum ErrorType {
    /** The master key could not be loaded or decrypted. Also counted per index. */
    KMS_KEY_ERROR("kms_key_error", true),
    /** The key health monitor applied a write or read block to an index. Also counted per index. */
    KMS_INDEX_BLOCKED("kms_index_blocked", true),
    /** Encrypted data or a footer failed authentication: corruption, tampering or a wrong key. Also counted per index. */
    AUTH_FAILURE("auth_failure", true),
    /** A block load gave up because the segment pool stayed exhausted. */
    POOL_EXHAUSTED("pool_exhausted"),
    /** A best-effort readahead task failed with an I/O error. */
    READAHEAD_FAILURE("readahead_failure"),
    INDEX_INPUT_ERROR("index_input_error"),
    INDEX_OUTPUT_ERROR("index_output_error"),
    DIRECTORY_CREATION_ERROR("directory_creation_error"),
    CLOSE_SEGMENT_ERROR("close_segment_error"),
    INC_SEGMENT_ERROR("inc_segment_error"),
    DEC_SEGMENT_ERROR("dec_segment_error");

    private final String value;
    private final boolean indexLevel;

    ErrorType(String value) {
        this(value, false);
    }

    ErrorType(String value, boolean indexLevel) {
        this.value = value;
        this.indexLevel = indexLevel;
    }

    /**
     * Whether the error affects one index and is also counted in {@code crypto.index.error.total}.
     */
    public boolean isIndexLevel() {
        return indexLevel;
    }

    public String getValue() {
        return value;
    }
}
