// Vercel Serverless Handler
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const app = require('../server/index');

// Export for Vercel - this makes the Express app handle requests
module.exports = app;
