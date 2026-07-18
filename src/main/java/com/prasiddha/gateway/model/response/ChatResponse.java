package com.prasiddha.gateway.model.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

/** Unified response — same shape regardless of which provider handled it */
@Data @Builder(toBuilder = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChatResponse {
    private String requestId;
    private String content;
    private String provider;
    private String model;
    private TokenUsage usage;
    private long latencyMs;
    /** True when the output scanner stripped or modified the response */
    private boolean outputSanitised;
    /** Non-null only when a provider fallback occurred — the provider originally requested. */
    private String requestedProvider;
    /** True when a different provider served this request after the requested one failed. */
    private boolean fellBack;
    /**
     * True when a FREE provider served this request at $0 after a paid provider was
     * usage-blocked or the caller's budget was exhausted (F6). Quality may be lower.
     */
    private boolean degraded;
    /** Why degradation happened: "paid_quota_exhausted" | "daily_budget_exceeded". Null unless degraded. */
    private String fallbackReason;

    @Data @Builder
    public static class TokenUsage {
        private int promptTokens;
        private int completionTokens;
        private int totalTokens;
    }
}
