const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
      new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
      new winston.transports.File({ filename: 'logs/server.log' }),
    ],
  });

if( process.env.NODE_ENV !== 'production' ){

    const customFormat = winston.format.printf( ({level,message,timestamp}) => {
        return `${timestamp} [${level}]: ${message}`;
    })

    logger.add( new winston.transports.Console({
        level: 'debug',
        format: winston.format.combine(
            winston.format.colorize({ all: true }),
            winston.format.timestamp(),
            customFormat
        )
    }));
}

exports.logger = logger;