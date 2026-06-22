package com.prasiddha.gateway.model.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

/** Unified response — same shape regardless of which provider handled it */
@Data @Builder
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

    @Data @Builder
    public static class TokenUsage {
        private int promptTokens;
        private int completionTokens;
        private int totalTokens;
    }
}
