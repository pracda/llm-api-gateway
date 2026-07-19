package com.prasiddha.gateway.service;

/**
 * Stateful, single-stream scanner for the mid-stream abort defence (F4). Maintains a small
 * sliding overlap buffer across chunks so a canary token or secret split across a chunk boundary
 * is still caught. Cheap: only the exact/secret patterns run, over a bounded window.
 *
 * <p>Not thread-safe by design — one instance per stream, driven sequentially by the reactive
 * pipeline. Honest limit: tokens already emitted can't be recalled, so this shrinks a leak, it
 * doesn't eliminate the first-N-token exposure.
 */
public final class StreamLeakScanner {

    /** Retained tail length — must exceed the longest secret/canary so cross-chunk splits are caught. */
    static final int OVERLAP = 256;

    private final OutputScanService outputScan;
    private final StringBuilder window = new StringBuilder();

    public StreamLeakScanner(OutputScanService outputScan) {
        this.outputScan = outputScan;
    }

    /**
     * Feeds the next text delta and returns a leak if the running window now contains one, else null.
     * The window is trimmed to the last {@link #OVERLAP} characters after each check.
     */
    public OutputScanService.StreamLeak inspect(String delta) {
        if (delta == null || delta.isEmpty()) {
            return null;
        }
        window.append(delta);
        OutputScanService.StreamLeak leak = outputScan.findStreamingLeak(window.toString());
        if (window.length() > OVERLAP) {
            window.delete(0, window.length() - OVERLAP);
        }
        return leak;
    }
}
