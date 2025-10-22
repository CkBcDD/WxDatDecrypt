const LEVEL_PRIORITY = { error: 0, warn: 1, info: 2, debug: 3 };
let currentLevel = 'info';

const log = (level, ...args) => {
    if (LEVEL_PRIORITY[level] <= LEVEL_PRIORITY[currentLevel]) {
        console[level === 'debug' ? 'log' : level](
            `[${new Date().toISOString()}][${level.toUpperCase()}]`,
            ...args,
        );
    }
};

const logger = {
    setLevel(nextLevel) {
        if (LEVEL_PRIORITY[nextLevel] !== undefined) currentLevel = nextLevel;
    },
    error: (...args) => log('error', ...args),
    warn: (...args) => log('warn', ...args),
    info: (...args) => log('info', ...args),
    debug: (...args) => log('debug', ...args),
};

export default logger;