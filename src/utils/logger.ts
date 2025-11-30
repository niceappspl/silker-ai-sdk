import { SilkerOptions } from '../types/options';

export interface Logger {
    info(message: string, ...args: any[]): void;
    warn(message: string, ...args: any[]): void;
    error(message: string, ...args: any[]): void;
    debug(message: string, ...args: any[]): void;
}

class DefaultLogger implements Logger {
    info(message: string, ...args: any[]): void {
        // No-op by default to keep user logs clean, unless we want some info?
        // The requirement says: "usuń te loggery nie chcemy ich" (remove these loggers we don't want them)
        // "console.log w kodzie produkcyjnym SDK to zła praktyka"
        // So default info should be silent or very minimal?
        // But user said "używać options.logger ... lub logować tylko przy debug: true".
        // So default implementation uses console but ONLY if debug is checked?
        // But Logger interface doesn't know about options.
        // I will make a getLogger(options) helper.
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
             // Warnings might be important even without debug, but let's follow "don't pollute" rule
             // Maybe only critical warnings?
             // User said "console.log ... zła praktyka". warn/error might be acceptable for real issues.
             // But let's stick to: if debug, log everything. If not, log only errors?
             // "logować tylko przy debug: true" implies mostly everything.
             // But errors should probably be logged?
             // I'll assume errors/warns are okay if they are critical, but info/debug require options.debug.
             if (options.debug) console.warn(message, ...args);
        },
        error: (message: string, ...args: any[]) => {
            // Errors should always be visible? Or only if debug?
            // "SDK nigdy nie powinno wywalić aplikacji hosta."
            // If we swallow errors, user won't know why it's not working.
            // Let's log errors to console.error always, but prefix them.
            console.error(message, ...args);
        },
        debug: (message: string, ...args: any[]) => {
            if (options.debug) {
                console.log(message, ...args); // Debug level using log or debug
            }
        }
    };
}

