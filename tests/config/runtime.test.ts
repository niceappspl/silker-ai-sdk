import { getRuntimeConfig, updateRuntimeConfig, setGlobalOptions } from '../../src/config/runtime';

describe('getRuntimeConfig', () => {
  it('should return current runtime configuration', () => {
    const config = getRuntimeConfig();
    expect(config).toBeDefined();
    expect(typeof config.debug).toBe('boolean');
    expect(typeof config.proxyMode).toBe('boolean');
    expect(typeof config.rateLimitThreshold).toBe('number');
    expect(typeof config.slowRequestThreshold).toBe('number');
    expect(typeof config.enableAuditLogging).toBe('boolean');
    expect(typeof config.enablePerformanceMonitoring).toBe('boolean');
    expect(Array.isArray(config.customRules)).toBe(true);
  });

  it('should return a copy of config', () => {
    const config1 = getRuntimeConfig();
    const config2 = getRuntimeConfig();
    expect(config1).not.toBe(config2);
    expect(config1).toEqual(config2);
  });
});

describe('updateRuntimeConfig', () => {
  beforeEach(() => {
    updateRuntimeConfig({
      debug: false,
      rateLimitThreshold: 5,
      slowRequestThreshold: 5000
    });
  });

  it('should update single configuration value', () => {
    const result = updateRuntimeConfig({ debug: true });
    expect(result.success).toBe(true);
    expect(result.updated).toContain('debug');
    
    const config = getRuntimeConfig();
    expect(config.debug).toBe(true);
  });

  it('should update multiple configuration values', () => {
    const result = updateRuntimeConfig({
      rateLimitThreshold: 10,
      slowRequestThreshold: 3000,
      debug: true
    });
    expect(result.success).toBe(true);
    expect(result.updated.length).toBe(3);
    expect(result.updated).toContain('rateLimitThreshold');
    expect(result.updated).toContain('slowRequestThreshold');
    expect(result.updated).toContain('debug');
    
    const config = getRuntimeConfig();
    expect(config.rateLimitThreshold).toBe(10);
    expect(config.slowRequestThreshold).toBe(3000);
    expect(config.debug).toBe(true);
  });

  it('should ignore invalid keys', () => {
    const originalConfig = getRuntimeConfig();
    const result = updateRuntimeConfig({
      invalidKey: 'value',
      anotherInvalidKey: 123
    } as any);
    
    expect(result.success).toBe(false);
    expect(result.updated.length).toBe(0);
    
    const config = getRuntimeConfig();
    expect(config).toEqual(originalConfig);
  });

  it('should update partial configuration', () => {
    const originalConfig = getRuntimeConfig();
    const result = updateRuntimeConfig({
      rateLimitThreshold: 15
    });
    
    expect(result.success).toBe(true);
    expect(result.updated).toContain('rateLimitThreshold');
    
    const config = getRuntimeConfig();
    expect(config.rateLimitThreshold).toBe(15);
    expect(config.slowRequestThreshold).toBe(originalConfig.slowRequestThreshold);
  });

  it('should propagate debug option to globalOptions', () => {
    setGlobalOptions({ debug: false });
    updateRuntimeConfig({ debug: true });
    
    const config = getRuntimeConfig();
    expect(config.debug).toBe(true);
  });

  it('should update customRules', () => {
    const customRules = [{ pattern: 'test', action: 'block' }];
    const result = updateRuntimeConfig({ customRules });
    
    expect(result.success).toBe(true);
    expect(result.updated).toContain('customRules');
    
    const config = getRuntimeConfig();
    expect(config.customRules).toEqual(customRules);
  });

  it('should update enableAuditLogging', () => {
    const result = updateRuntimeConfig({ enableAuditLogging: false });
    
    expect(result.success).toBe(true);
    const config = getRuntimeConfig();
    expect(config.enableAuditLogging).toBe(false);
  });

  it('should update enablePerformanceMonitoring', () => {
    const result = updateRuntimeConfig({ enablePerformanceMonitoring: false });
    
    expect(result.success).toBe(true);
    const config = getRuntimeConfig();
    expect(config.enablePerformanceMonitoring).toBe(false);
  });

  it('should return success false for empty updates', () => {
    const result = updateRuntimeConfig({});
    expect(result.success).toBe(false);
    expect(result.updated.length).toBe(0);
  });
});

