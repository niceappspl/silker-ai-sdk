import { SilkerOptions } from '../types/options';

export interface Logger {
    info(message: string, ...args: any[]): void;
    warn(message: string, ...args: any[]): void;
    error(message: string, ...args: any[]): void;
    debug(message: string, ...args: any[]): void;
}

class DefaultLogger implements Logger {
    info(message: string, ...args: any[]): void {
        // No-op by default
    }
    warn(message: string, ...args: any[]): void {
        console.warn(message, ...args);
    }
    error(message: string, ...args: any[]): void {
        console.error(message, ...args);
    }
    debug(message: string, ...args: any[]): void {
        // No-op
    }
}

export const defaultLogger = new DefaultLogger();

export function createLogger(options: SilkerOptions): Logger {
    if (options.logger) {
        return options.logger;
    }

    return {
        info: (message: string, ...args: any[]) => {
            if (options.debug) {
                console.log(message, ...args);
            }
        },
        warn: (message: string, ...args: any[]) => {
             if (options.debug) console.warn(message, ...args);
        },
        error: (message: string, ...args: any[]) => {
            console.error(message, ...args);
        },
        debug: (message: string, ...args: any[]) => {
            if (options.debug) {
                console.log(message, ...args); // Debug level using log or debug
            }
        }
    };
}

