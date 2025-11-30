import axios from 'axios';
import { SilkerOptions } from '../types';
import { sanitizeSensitiveData } from './sanitization';

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
    private readonly FLUSH_DELAY = 5000; // 5 seconds
    private readonly MAX_BATCH_SIZE = 50;
    private isFlushing = false;

    constructor() { }

    /**
     * Configures the telemetry client with Silker options.
     * Should be called at least once before sending data.
     */
    public configure(options: SilkerOptions) {
        this.options = options;
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

    private async flush() {
        if (this.isFlushing || this.queue.length === 0 || !this.options) return;

        this.isFlushing = true;
        const batch = this.queue.splice(0, this.MAX_BATCH_SIZE);
        const options = this.options;

        try {
            const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
            let baseUrl = options.endpoint || options.dashboardUrl || (isDev ? 'http://localhost:3000' : 'https://api.silkerai.com');

            // Normalize URL - remove /api suffix if present
            if (baseUrl.includes('/api')) {
                baseUrl = baseUrl.replace('/api', '');
            }
            baseUrl = baseUrl.replace(/\/$/, '');

            const ingestUrl = `${baseUrl}/api/ingest`;

            await axios.post(ingestUrl, { events: batch }, {
                headers: {
                    'x-api-key': options.apiKey,
                    'Content-Type': 'application/json',
                    'x-silker-client-version': '1.0.0'
                },
                timeout: 10000 // Increased timeout for batch
            });

        } catch (error) {
            if (options.debug) {
                console.error('🚨 [Silker SDK] Failed to flush telemetry batch:', (error as Error).message);
            }
            // In a more advanced implementation, we could retry failed items or put them back in queue
            // For now, to avoid memory leaks, we drop them if they fail repeatedly, 
            // but here we just lost this batch.
        } finally {
            this.isFlushing = false;
        }
    }
}

export const telemetry = new TelemetryClient();
