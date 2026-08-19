// backend/lib/events.js
// A single-process pub/sub bus. Real-time `entity.subscribe()` calls on the
// frontend are served over Server-Sent Events, backed by this EventEmitter —
// good enough for a single backend instance; swap for Redis pub/sub if you
// ever run multiple backend processes behind a load balancer.
import { EventEmitter } from 'node:events';

export const bus = new EventEmitter();
bus.setMaxListeners(0);

export function publish(entity, type, record) {
  bus.emit(entity, { type, record });
  bus.emit('*', { entity, type, record });
}
