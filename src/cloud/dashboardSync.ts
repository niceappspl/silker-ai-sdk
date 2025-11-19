import axios from 'axios';
import { SilkerOptions } from '../types';

/**
 * Sends alert data to the Silker Dashboard.
 * @param options - Global Silker options containing dashboard URL and credentials
 * @param data - The alert payload to send
 */
export async function pushDashboardData(
    options: SilkerOptions | null,
    data: any
) {
    if (options?.debug) {
        console.log('🔍 pushDashboardData called with:', {
            hasDashboardUrl: !!options?.dashboardUrl,
            hasApiKey: !!options?.apiKey,
            dashboardUrl: options?.dashboardUrl,
            dataKeys: Object.keys(data)
        });
    }

    if (!options?.dashboardUrl || !options?.apiKey) {
        if (options?.debug) {
            console.log('⚠️ Skipping dashboard push - missing dashboardUrl or apiKey');
        }
        return;
    }

    const payload = {
        appId: options.appId,
        tokenId: options.tokenId,
        ...data,
    };

    if (options.debug) {
        console.log('📤 Sending to dashboard:', `${options.dashboardUrl}/api/dashboard/sync`);
        console.log('📦 Payload:', JSON.stringify(payload, null, 2));
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
            if (options.debug) {
                console.error('❌ Failed to push data to dashboard:', err.message);
            }
        });
    } catch (error) {
        if (options.debug) {
            console.error('❌ Failed to initiate dashboard push:', error);
        }
    }
}
