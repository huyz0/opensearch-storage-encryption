/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.util.List;
import java.util.Map;

import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.test.rest.OpenSearchRestTestCase;

/**
 * A Painless script that reads a block nobody has read yet makes the plugin open the file from
 * inside the script's call stack. Scripts have no file permissions, so the open must run in a
 * privileged block or the node's runtime agent rejects it. This needs a real node (the agent is
 * only active there), which is why it lives in the yamlRestTest source set.
 *
 * <p>The test cluster caches a single file channel ({@code node.store.crypto.max_file_channels: 1}),
 * so after the reader opens several segments, the first segment's channel is gone and its doc
 * values blocks are still cold when the script reaches them.
 */
public class ScriptColdReadIT extends OpenSearchRestTestCase {

    private static final String INDEX = "test-crypto-script-cold-read";
    private static final int SEGMENTS = 3;
    private static final int DOCS_PER_SEGMENT = 20_000;

    @SuppressWarnings("unchecked")
    public void testPainlessScriptReadsColdEncryptedBlocks() throws Exception {
        Request create = new Request("PUT", "/" + INDEX);
        create.setJsonEntity("""
            {
              "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": -1,
                "index.store.type": "cryptofs",
                "index.store.crypto.key_provider": "dummy",
                "index.merge.policy.segments_per_tier": 100
              },
              "mappings": { "properties": { "price": { "type": "long" } } }
            }""");
        client().performRequest(create);

        long expectedMax = Long.MIN_VALUE;
        int id = 0;
        for (int segment = 0; segment < SEGMENTS; segment++) {
            StringBuilder bulk = new StringBuilder();
            for (int i = 0; i < DOCS_PER_SEGMENT; i++) {
                // Random values keep doc values wide, so the data spans many 8 KB blocks
                long price = randomLongBetween(0, Long.MAX_VALUE / 2);
                expectedMax = Math.max(expectedMax, price);
                bulk.append("{\"index\":{\"_id\":\"").append(id++).append("\"}}\n");
                bulk.append("{\"price\":").append(price).append("}\n");
            }
            Request bulkRequest = new Request("POST", "/" + INDEX + "/_bulk");
            bulkRequest.setJsonEntity(bulk.toString());
            Map<String, Object> bulkResponse = entityAsMap(client().performRequest(bulkRequest));
            assertEquals(Boolean.FALSE, bulkResponse.get("errors"));
            client().performRequest(new Request("POST", "/" + INDEX + "/_flush"));
        }
        // Reopen the shard: closing it drops its cached blocks, and the new reader only reads headers and footers
        client().performRequest(new Request("POST", "/" + INDEX + "/_close"));
        Request open = new Request("POST", "/" + INDEX + "/_open");
        open.addParameter("wait_for_active_shards", "all");
        client().performRequest(open);
        ensureGreen(INDEX);

        Request search = new Request("POST", "/" + INDEX + "/_search");
        search.setJsonEntity("""
            {
              "size": 1,
              "track_total_hits": true,
              "query": {
                "script_score": {
                  "query": { "match_all": {} },
                  "script": { "lang": "painless", "source": "doc['price'].value / 1.0e10" }
                }
              },
              "script_fields": {
                "price": { "script": { "lang": "painless", "source": "doc['price'].value" } }
              }
            }""");
        Response response = client().performRequest(search);
        Map<String, Object> body = entityAsMap(response);

        Map<String, Object> shards = (Map<String, Object>) body.get("_shards");
        assertEquals("shard failures: " + shards.get("failures"), 0, shards.get("failed"));
        Map<String, Object> hits = (Map<String, Object>) body.get("hits");
        assertEquals(SEGMENTS * DOCS_PER_SEGMENT, ((Map<String, Object>) hits.get("total")).get("value"));
        Map<String, Object> top = ((List<Map<String, Object>>) hits.get("hits")).get(0);
        List<Object> price = (List<Object>) ((Map<String, Object>) top.get("fields")).get("price");
        assertEquals(expectedMax, ((Number) price.get(0)).longValue());
    }
}
