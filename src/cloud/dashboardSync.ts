import axios from 'axios';
import { SilkerOptions } from '../types';
import { createLogger } from '../utils/logger';

/**
 * Sends alert data to the Silker Dashboard.
 * @param options - Global Silker options containing dashboard URL and credentials
 * @param data - The alert payload to send
 */
export async function pushDashboardData(
    options: SilkerOptions | null,
    data: any
) {
    const logger = options ? createLogger(options) : null;

    if (options?.debug) {
        logger?.debug('🔍 pushDashboardData called with:', {
            hasDashboardUrl: !!options?.dashboardUrl,
            hasApiKey: !!options?.apiKey,
            dashboardUrl: options?.dashboardUrl,
            dataKeys: Object.keys(data)
        });
    }

    if (!options?.dashboardUrl || !options?.apiKey) {
        if (options?.debug) {
            logger?.warn('⚠️ Skipping dashboard push - missing dashboardUrl or apiKey');
        }
        return;
    }

    const payload = {
        appId: options.appId,
        tokenId: options.tokenId,
        ...data,
    };

    if (options.debug) {
        logger?.debug('📤 Sending to dashboard:', `${options.dashboardUrl}/api/dashboard/sync`);
        // Avoid logging full payload in production unless absolutely necessary debug
        logger?.debug('📦 Payload keys:', Object.keys(payload));
    }

    try {
        // Fire and forget - don't await to avoid blocking the request
        axios.post(`${options.dashboardUrl}/api/dashboard/sync`, payload, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${options.apiKey}`,
            },
            timeout: 5000 // 5s timeout
        }).catch(err => {
             logger?.error('❌ Failed to push data to dashboard:', err.message);
        });
    } catch (error) {
         logger?.error('❌ Failed to initiate dashboard push:', error);
    }
}
