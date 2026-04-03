'use strict';

const mongoose = require('mongoose');
const logger = require('../utils/logger');

const MAX_RETRIES = 5;
const RETRY_INTERVAL_MS = 5000;

const options = {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  maxPoolSize: 10,
  minPoolSize: 2,
};

let retryCount = 0;

async function connectWithRetry() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    logger.error('MONGODB_URI is not defined');
    process.exit(1);
  }

  try {
    await mongoose.connect(uri, options);
    retryCount = 0;
  } catch (err) {
    retryCount += 1;
    logger.error(`MongoDB connection attempt ${retryCount} failed: ${err.message}`);

    if (retryCount >= MAX_RETRIES) {
      logger.error('Max MongoDB connection retries reached. Exiting.');
      process.exit(1);
    }

    logger.info(`Retrying MongoDB connection in ${RETRY_INTERVAL_MS / 1000}s...`);
    await new Promise((resolve) => setTimeout(resolve, RETRY_INTERVAL_MS));
    return connectWithRetry();
  }
}

mongoose.connection.on('connected', () => {
  logger.info('MongoDB connected');
});

mongoose.connection.on('error', (err) => {
  logger.error(`MongoDB error: ${err.message}`);
});

mongoose.connection.on('disconnected', () => {
  logger.warn('MongoDB disconnected');
});

module.exports = { connectWithRetry };
