/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;


import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Cache for VP Status Listeners supporting long polling.
 * When a client polls for VP request status, their listener is registered here.
 * When a VP submission arrives, listeners are notified.
 */
public final class VPStatusListenerCache {

    /**
     * Default long polling timeout in milliseconds (60 seconds).
     */
    private static final long DEFAULT_POLLING_TIMEOUT_MS = 60000L;

    /**
     * Cleanup interval in milliseconds.
     */
    private static final long CLEANUP_INTERVAL_MS = 10000L;

    /**
     * Map of request ID to list of listeners.
     */
    private final Map<String, List<StatusListener>> listenersByRequestId;

    /**
     * Cleanup executor.
     */
    private final ScheduledExecutorService cleanupExecutor;

    /**
     * Listener entry with callback and timeout tracking.
     */
    public static class StatusListener {

        private final String listenerId;
        private final long createdAt;
        private final long timeoutAt;
        private final StatusCallback callback;
        private volatile boolean notified;

        /**
         * Constructor.
         *
         * @param id      Unique listener ID
         * @param timeout Timeout in milliseconds
         * @param cb      Callback to invoke on status change
         */
        public StatusListener(final String id,
                final long timeout,
                final StatusCallback cb) {

            this.listenerId = id;
            this.createdAt = System.currentTimeMillis();
            this.timeoutAt = this.createdAt + timeout;
            this.callback = cb;
            this.notified = false;
        }

        /**
         * Get listener ID.
         *
         * @return Listener ID
         */
        public String getListenerId() {

            return listenerId;
        }

        /**
         * Check if listener has timed out.
         *
         * @return true if timed out
         */
        public boolean isTimedOut() {

            return System.currentTimeMillis() > timeoutAt;
        }

        /**
         * Check if already notified.
         *
         * @return true if notified
         */
        public boolean isNotified() {

            return notified;
        }

        /**
         * Notify this listener with a status.
         *
         * @param status The status to notify with
         */
        public void notify(final String status) {

            if (!notified) {
                notified = true;
                if (callback != null) {
                    callback.onStatusChange(status);
                }
            }
        }

        /**
         * Notify this listener of timeout.
         */
        public void notifyTimeout() {

            if (!notified) {
                notified = true;
                if (callback != null) {
                    callback.onTimeout();
                }
            }
        }
    }

    /**
     * Callback interface for status changes.
     */
    public interface StatusCallback {

        /**
         * Called when status changes.
         *
         * @param status The new status
         */
        void onStatusChange(String status);

        /**
         * Called when the listener times out.
         */
        void onTimeout();

    }

    /**
     * Private constructor for singleton.
     */
    private VPStatusListenerCache() {

        this.listenersByRequestId = new ConcurrentHashMap<>();

        // Schedule periodic cleanup
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "VPStatusListenerCache-Cleanup");
            t.setDaemon(true);
            return t;
        });

        this.cleanupExecutor.scheduleAtFixedRate(
                this::cleanupExpiredListeners,
                CLEANUP_INTERVAL_MS,
                CLEANUP_INTERVAL_MS,
                TimeUnit.MILLISECONDS);

    }

    /**
     * Get singleton instance.
     *
     * @return VPStatusListenerCache instance
     */
    public static synchronized VPStatusListenerCache getInstance() {
        return Holder.INSTANCE;
    }

    /**
     * Lazy-loaded singleton holder.
     */
    private static final class Holder {

        private static final VPStatusListenerCache INSTANCE = new VPStatusListenerCache();

        private Holder() {
        }
    }

    /**
     * Register a listener for a request ID.
     *
     * @param requestId  Request ID to listen for
     * @param listenerId Unique listener ID
     * @param callback   Callback for status changes
     * @return The registered listener
     */
    public StatusListener registerListener(final String requestId,
            final String listenerId,
            final StatusCallback callback) {

        return registerListener(requestId, listenerId, DEFAULT_POLLING_TIMEOUT_MS,
                callback);
    }

    /**
     * Register a listener with custom timeout.
     *
     * @param requestId  Request ID to listen for
     * @param listenerId Unique listener ID
     * @param timeoutMs  Timeout in milliseconds
     * @param callback   Callback for status changes
     * @return The registered listener
     */
    public StatusListener registerListener(final String requestId,
            final String listenerId,
            final long timeoutMs,
            final StatusCallback callback) {

        StatusListener listener = new StatusListener(listenerId, timeoutMs, callback);

        listenersByRequestId.computeIfAbsent(requestId, k -> new CopyOnWriteArrayList<>())
                .add(listener);

        return listener;
    }

    /**
     * Notify all listeners for a request ID.
     *
     * @param requestId Request ID
     * @param status    Status to notify with
     */
    public void notifyListeners(final String requestId, final String status) {

        List<StatusListener> listeners = listenersByRequestId.get(requestId);
        if (listeners != null) {

            for (StatusListener listener : listeners) {
                if (!listener.isNotified()) {
                    listener.notify(status);

                }
            }

        }
    }


    /**
     * Remove a specific listener.
     *
     * @param requestId  Request ID
     * @param listenerId Listener ID to remove
     */
    public void removeListener(final String requestId, final String listenerId) {

        List<StatusListener> listeners = listenersByRequestId.get(requestId);
        if (listeners != null) {
            listeners.removeIf(l -> l.getListenerId().equals(listenerId));
        }
    }

    /**
     * Remove all listeners for a request.
     *
     * @param requestId Request ID
     */
    public void removeAllListeners(final String requestId) {

        listenersByRequestId.remove(requestId);
    }

    /**
     * Get listener count for a request.
     *
     * @param requestId Request ID
     * @return Number of listeners
     */
    public int getListenerCount(final String requestId) {

        List<StatusListener> listeners = listenersByRequestId.get(requestId);
        return listeners != null ? listeners.size() : 0;
    }

    /**
     * Check if there are any active listeners for a request.
     *
     * @param requestId Request ID
     * @return true if active listeners exist
     */
    public boolean hasActiveListeners(final String requestId) {

        List<StatusListener> listeners = listenersByRequestId.get(requestId);
        if (listeners == null || listeners.isEmpty()) {
            return false;
        }
        for (StatusListener listener : listeners) {
            if (!listener.isNotified() && !listener.isTimedOut()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Cleanup expired and notified listeners.
     */
    private void cleanupExpiredListeners() {

        Iterator<Map.Entry<String, List<StatusListener>>> entryIterator = listenersByRequestId.entrySet().iterator();

        while (entryIterator.hasNext()) {
            Map.Entry<String, List<StatusListener>> entry = entryIterator.next();
            List<StatusListener> listeners = entry.getValue();

            for (StatusListener listener : listeners) {
                if (listener.isTimedOut() && !listener.isNotified()) {
                    listener.notifyTimeout();
                }
            }

            listeners.removeIf(l -> l.isNotified() || l.isTimedOut());

            // Remove entry if no listeners remain
            if (listeners.isEmpty()) {
                entryIterator.remove();
            }
        }

    }

    /**
     * Get total number of active listeners across all requests.
     *
     * @return Total listener count
     */
    public int getTotalListenerCount() {

        int total = 0;
        for (List<StatusListener> listeners : listenersByRequestId.values()) {
            total += listeners.size();
        }
        return total;
    }

}
