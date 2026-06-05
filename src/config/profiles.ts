import { SilkerOptions, SilkerFeatures, ConfigProfile } from '../types';

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export interface ProfileConfig {
  features: SilkerFeatures;
}

export const CONFIG_PROFILES: Record<ConfigProfile, ProfileConfig> = {
  'strict': {
    features: {
      promptInjectionDetection: true,
      dataLeakageDetection: { strategy: 'block' },
      zeroTrustDetection: true,
      auditLogging: true,
      rateLimit: true,
      cloudCommunication: true,
      sqliDetection: true,
      xssDetection: true,
      pathTraversalDetection: true,
      csrfDetection: true,
      ssrfDetection: true,
      idorDetection: true,
      hostHeaderInjectionDetection: true,
      accessControlDetection: true,
      cryptographicValidation: true,
      authenticationValidation: true,
      ipBanning: true,
      disableLegacySecurity: false,
    }
  },
  'saas': {
    features: {
      promptInjectionDetection: true,
      dataLeakageDetection: { strategy: 'redact' },
      rateLimit: true,
      auditLogging: true,
      cloudCommunication: true,
      sqliDetection: true,
      xssDetection: true,
      pathTraversalDetection: true,
      csrfDetection: true,
      ssrfDetection: true,
      idorDetection: true,
      hostHeaderInjectionDetection: true,
      ipBanning: false,
      disableLegacySecurity: false,
    }
  },
  'audit': {
    features: {
      promptInjectionDetection: true,
      dataLeakageDetection: { strategy: 'monitor' },
      rateLimit: false,
      auditLogging: true,
      cloudCommunication: true,
      sqliDetection: false,
      xssDetection: false,
      pathTraversalDetection: false,
      csrfDetection: false,
      ssrfDetection: false,
      idorDetection: false,
      hostHeaderInjectionDetection: false,
      ipBanning: false,
      disableLegacySecurity: true,
    }
  }
};

function isObject(item: unknown): item is Record<string, unknown> {
  return item !== null && typeof item === 'object' && !Array.isArray(item);
}

export function deepMerge<T extends Record<string, unknown>>(target: T, source: DeepPartial<T>): T {
  const result = { ...target } as T;

  for (const key of Object.keys(source) as Array<keyof T>) {
    const sourceValue = source[key as keyof DeepPartial<T>];
    const targetValue = target[key];

    if (isObject(sourceValue) && isObject(targetValue)) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as DeepPartial<Record<string, unknown>>
      ) as T[keyof T];
    } else if (sourceValue !== undefined) {
      result[key] = sourceValue as T[keyof T];
    }
  }

  return result;
}

export function applyProfile(options: SilkerOptions): SilkerOptions {
  if (!options.profile || !CONFIG_PROFILES[options.profile]) {
    return options;
  }

  const profileConfig = CONFIG_PROFILES[options.profile];
  
  const mergedFeatures = deepMerge(
    profileConfig.features as Record<string, unknown>,
    (options.features || {}) as DeepPartial<Record<string, unknown>>
  ) as SilkerFeatures;

  return {
    ...options,
    features: mergedFeatures,
  };
}
