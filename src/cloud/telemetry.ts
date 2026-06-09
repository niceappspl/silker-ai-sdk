import axios from 'axios';
import { SilkerOptions } from '../types';
import { sanitizeSensitiveData } from './sanitization';
import { createLogger, Logger } from '../utils/logger';
import { syncBans } from '../detection/rateLimit';

type TelemetryType = 'threat' | 'request';

interface TelemetryItem {
    type: TelemetryType;
    payload: any;
    endpoint: string;
    timestamp: number;
}

class TelemetryClient {
    private queue: TelemetryItem[] = [];
    private flushInterval: NodeJS.Timeout | null = null;
    private options: SilkerOptions | null = null;
    private logger: Logger | null = null;
    private FLUSH_DELAY = 5000; // 5 seconds
    private MAX_BATCH_SIZE = 50;
    private isFlushing = false;
    private readonly MAX_QUEUE_SIZE = 1000; // Prevent memory leaks
    private sampleRate = 1; // Fraction of 'request' events to send (threats always 100%)
    private waitUntil: ((promise: Promise<unknown>) => void) | null = null;

    constructor() {
        // Detect serverless environment (Vercel, AWS Lambda, etc.)
        // In these environments, we need to flush immediately as the process may freeze
        if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY) {
            this.MAX_BATCH_SIZE = 1;
            this.FLUSH_DELAY = 0;
        }
    }

    /**
     * Configures the telemetry client with Silker options.
     * Should be called at least once before sending data.
     */
    public configure(options: SilkerOptions) {
        this.options = options;
        this.logger = createLogger(options);

        const rate = options.telemetry?.sampleRate;
        if (typeof rate === 'number' && rate >= 0 && rate <= 1) {
            this.sampleRate = rate;
        }
        if (typeof options.waitUntil === 'function') {
            this.waitUntil = options.waitUntil;
        }

        if (!this.flushInterval) {
            this.startFlushLoop();
        }
    }

    private startFlushLoop() {
        this.flushInterval = setInterval(() => this.flush(), this.FLUSH_DELAY);
        // Ensure the process doesn't hang on this interval if it's the only thing running
        if (this.flushInterval.unref) {
            this.flushInterval.unref();
        }
    }

    /**
     * Adds an item to the telemetry queue.
     * Data is automatically sanitized.
     *
     * NEVER blocks the request path: delivery is fire-and-forget. On serverless,
     * the flush promise is handed to `waitUntil` (if provided via options) so events
     * are delivered after the response is sent without adding latency; otherwise it
     * runs in the background (best-effort, may be cut short when the process freezes).
     */
    public push(type: TelemetryType, endpoint: string, data: any): void {
        // Sampling: drop a fraction of regular request events to cut latency/ingest cost.
        // Threats are always sent (security-critical).
        if (type === 'request' && this.sampleRate < 1 && Math.random() > this.sampleRate) {
            return;
        }

        // Prevent infinite queue growth if backend is unreachable
        if (this.queue.length >= this.MAX_QUEUE_SIZE) {
            // Drop oldest items (FIFO) to make space
            // We drop 10% of the queue to avoid constant shifting on full queue
            const dropCount = Math.ceil(this.MAX_QUEUE_SIZE * 0.1);
            this.queue.splice(0, dropCount);

            this.logger?.warn(`[Silker SDK] Telemetry queue full (${this.MAX_QUEUE_SIZE}). Dropped ${dropCount} oldest events.`);
        }

        // Sanitize data before queuing to ensure no sensitive info resides in memory/transit
        const sanitizedData = sanitizeSensitiveData(data);

        this.queue.push({
            type,
            endpoint,
            payload: sanitizedData,
            timestamp: Date.now()
        });

        this.scheduleFlush();
    }

    /**
     * Triggers delivery without ever blocking the caller.
     */
    private scheduleFlush(): void {
        const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);

        if (isServerless) {
            // Flush immediately, but off the request path. Prefer waitUntil so the
            // platform keeps the function alive until delivery completes.
            if (this.isFlushing) return;
            const flushPromise = this.flush().catch(() => {});
            if (this.waitUntil) {
                this.waitUntil(flushPromise);
            }
            return;
        }

        // Long-running processes: batch in the background.
        if (this.queue.length >= this.MAX_BATCH_SIZE) {
            this.flush().catch(() => {});
        }
    }

    private async flush(retryCount = 0) {
        if (this.isFlushing || this.queue.length === 0 || !this.options) return;

        this.isFlushing = true;
        
        try {
            const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);
            
            // Take as many items as we can
            // In serverless, we want to send EVERYTHING at once to avoid process freeze issues
            const currentBatchSize = isServerless ? this.queue.length : (this.queue.length > 500 ? 100 : this.MAX_BATCH_SIZE);
            const batch = this.queue.slice(0, currentBatchSize);
            const options = this.options;

            const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
            let baseUrl = options.endpoint || (isDev ? 'http://localhost:3000' : 'https://platform.silkerai.com');

            // Normalize URL - remove /api suffix if present
            if (baseUrl.includes('/api')) {
                baseUrl = baseUrl.replace('/api', '');
            }
            baseUrl = baseUrl.replace(/\/$/, '');

            const ingestUrl = `${baseUrl}/api/ingest`;

            const response = await axios.post(ingestUrl, { events: batch }, {
                headers: {
                    'x-api-key': options.apiKey,
                    'Content-Type': 'application/json',
                    'x-silker-client-version': '1.0.24'
                },
                timeout: isServerless ? 10000 : 5000 // Higher timeout for serverless batches
            });

            this.logger?.debug(`[Silker SDK] Flushed batch of ${batch.length} items. Status: ${response.status}`);

            // Update local ban list from dashboard response
            if (response.data?.data?.bannedIps) {
                syncBans(response.data.data.bannedIps);
            }

            // On success, remove the batch from queue
            this.queue.splice(0, batch.length);

            // In serverless, we don't use the background loop for remaining items as it will be killed
            // We expect the next request or the current request's push to handle it
            if (!isServerless && this.queue.length > 0) {
                this.isFlushing = false;
                const continueTimer = setTimeout(() => this.flush(), 10);
                if (continueTimer.unref) {
                    continueTimer.unref();
                }
                return;
            }

        } catch (error: any) {
            // ... error handling ...
            // Log detailed error information
            this.logger?.error('[Silker SDK] Flush error details:', {
                message: error.message,
                code: error.code,
                status: error.response?.status,
                statusText: error.response?.statusText,
                data: error.response?.data,
                url: error.config?.url
            });

            const isRetryable = !error.response || // Network error
                               error.code === 'ECONNRESET' || 
                               error.code === 'ETIMEDOUT' || 
                               (error.response && error.response.status >= 500) ||
                               (error.response && error.response.status === 429); // Rate limit
            
            if (isRetryable && retryCount < 3) {
                this.logger?.warn(`[Silker SDK] Flush failed, retrying (${retryCount + 1}/3)...`);
                this.isFlushing = false;
                // Wait with exponential backoff: 1s, 2s, 4s
                const retryTimer = setTimeout(() => this.flush(retryCount + 1), 1000 * Math.pow(2, retryCount));
                if (retryTimer.unref) {
                    retryTimer.unref();
                }
                return;
            }

            this.logger?.error('[Silker SDK] Failed to flush telemetry batch after retries');
            // If max retries reached or non-retryable error (e.g. 401), drop the batch to unblock queue
            // We drop only the batch that failed, not the whole queue
            const batchSizeToDrop = Math.min(this.queue.length, this.MAX_BATCH_SIZE);
            this.queue.splice(0, batchSizeToDrop);
        } finally {
            this.isFlushing = false;
        }
    }
}

export const telemetry = new TelemetryClient();
