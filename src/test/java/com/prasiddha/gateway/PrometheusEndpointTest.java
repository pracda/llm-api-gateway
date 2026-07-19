package com.prasiddha.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * F5 — /actuator/prometheus is exposed, unauthenticated (so a scraper can reach it), and includes
 * the gateway's custom meters. {@code @AutoConfigureObservability} enables the metrics-export
 * auto-config that @SpringBootTest disables by default, mirroring the production runtime.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureObservability
@ActiveProfiles("test")
@DisplayName("Prometheus scrape endpoint")
class PrometheusEndpointTest {

    @Autowired MockMvc mockMvc;

    @Test
    void prometheusEndpointIsPublicAndExposesGatewayMeters() throws Exception {
        mockMvc.perform(get("/actuator/prometheus"))
            .andExpect(status().isOk())
            // gateway.jailbreak.score is registered eagerly at startup, so it's always present.
            .andExpect(content().string(org.hamcrest.Matchers.containsString("gateway_jailbreak_score")));
    }
}
