package com.prasiddha.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Holds currently-connected admin dashboard SSE clients in memory.
 *
 * Single-instance deployment (no load balancer, no replica story anywhere
 * in this project) — an in-memory list is the right level of complexity.
 * If this ever runs multi-instance, swap this class's internals for
 * Redis Pub/Sub without touching any caller.
 */
@Slf4j
@Service
public class SseEmitterRegistry {

    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public SseEmitter register() {
        SseEmitter emitter = new SseEmitter(0L); // no timeout — overrides the 30s MVC default
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(e -> emitters.remove(emitter));
        log.debug("SSE client connected — active={}", emitters.size());
        return emitter;
    }

    public void broadcast(String eventName, Object payload) {
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name(eventName).data(payload));
            } catch (IOException | IllegalStateException e) {
                emitters.remove(emitter);
            }
        }
    }

    /** Keeps idle SSE connections alive through proxies that close quiet sockets. */
    @Scheduled(fixedRate = 15_000)
    public void heartbeat() {
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().comment("ping"));
            } catch (IOException | IllegalStateException e) {
                emitters.remove(emitter);
            }
        }
    }
}
