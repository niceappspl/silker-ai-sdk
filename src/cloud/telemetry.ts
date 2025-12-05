import axios from 'axios';
import { SilkerOptions } from '../types';
import { sanitizeSensitiveData } from './sanitization';
import { createLogger, Logger } from '../utils/logger';

type TelemetryType = 'alert' | 'threat' | 'request';

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
    private readonly FLUSH_DELAY = 5000; // 5 seconds
    private readonly MAX_BATCH_SIZE = 50;
    private isFlushing = false;
    private readonly MAX_QUEUE_SIZE = 1000; // Prevent memory leaks

    constructor() { }

    /**
     * Configures the telemetry client with Silker options.
     * Should be called at least once before sending data.
     */
    public configure(options: SilkerOptions) {
        this.options = options;
        this.logger = createLogger(options);
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
     */
    public push(type: TelemetryType, endpoint: string, data: any) {
        // Prevent infinite queue growth if backend is unreachable
        if (this.queue.length >= this.MAX_QUEUE_SIZE) {
            // Drop oldest items (FIFO) to make space
            // We drop 10% of the queue to avoid constant shifting on full queue
            const dropCount = Math.ceil(this.MAX_QUEUE_SIZE * 0.1);
            this.queue.splice(0, dropCount);
            
            this.logger?.warn(`⚠️ [Silker SDK] Telemetry queue full (${this.MAX_QUEUE_SIZE}). Dropped ${dropCount} oldest events.`);
        }

        // Sanitize data before queuing to ensure no sensitive info resides in memory/transit
        const sanitizedData = sanitizeSensitiveData(data);

        this.queue.push({
            type,
            endpoint,
            payload: sanitizedData,
            timestamp: Date.now()
        });

        // If queue is too large, flush immediately
        if (this.queue.length >= this.MAX_BATCH_SIZE) {
            this.flush();
        }
    }

    private async flush(retryCount = 0) {
        if (this.isFlushing || this.queue.length === 0 || !this.options) return;

        this.isFlushing = true;
        // Peek at batch without removing yet, in case of failure
        const batch = this.queue.slice(0, this.MAX_BATCH_SIZE);
        const options = this.options;

        try {
            const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
            let baseUrl = options.endpoint || (isDev ? 'http://localhost:3000' : 'https://api.silkerai.com');

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
                    'x-silker-client-version': '1.0.0'
                },
                timeout: 10000 // Increased timeout for batch
            });

            this.logger?.debug(`[Silker SDK] Flushed batch of ${batch.length} items. Status: ${response.status}`);

            // On success, remove the batch from queue
            this.queue.splice(0, batch.length);

        } catch (error: any) {
            const isRetryable = !error.response || // Network error
                               error.code === 'ECONNRESET' || 
                               error.code === 'ETIMEDOUT' || 
                               (error.response && error.response.status >= 500) ||
                               (error.response && error.response.status === 429); // Rate limit
            
            if (isRetryable && retryCount < 3) {
                this.logger?.warn(`⚠️ [Silker SDK] Flush failed, retrying (${retryCount + 1}/3)...`);
                this.isFlushing = false;
                // Wait with exponential backoff: 1s, 2s, 4s
                setTimeout(() => this.flush(retryCount + 1), 1000 * Math.pow(2, retryCount));
                return;
            }

            this.logger?.error('🚨 [Silker SDK] Failed to flush telemetry batch:', (error as Error).message);
            // If max retries reached or non-retryable error (e.g. 401), drop the batch to unblock queue
            this.queue.splice(0, batch.length);
        } finally {
            this.isFlushing = false;
        }
    }
}

export const telemetry = new TelemetryClient();
