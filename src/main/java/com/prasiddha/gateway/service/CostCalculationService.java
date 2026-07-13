package com.prasiddha.gateway.service;

import com.prasiddha.gateway.config.PricingProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CostCalculationService {

    private final PricingProperties pricingProperties;

    /** Unknown provider/model combinations return 0.0 (logged) rather than failing the request. */
    public double computeCostUsd(String provider, String model, int promptTokens, int completionTokens) {
        PricingProperties.ModelPricing pricing = pricingProperties.lookup(provider, model);
        if (pricing == null) {
            log.warn("No pricing configured for provider={} model={} — costUsd recorded as 0", provider, model);
            return 0.0;
        }
        return (promptTokens / 1_000_000.0) * pricing.getInputPerMillion()
             + (completionTokens / 1_000_000.0) * pricing.getOutputPerMillion();
    }
}
