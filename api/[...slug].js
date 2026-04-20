// Catch-all handler for all requests
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
module.exports = require('../server/index');
