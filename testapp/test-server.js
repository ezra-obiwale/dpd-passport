process.chdir(__dirname);
var deployd = require('deployd');

var ENV = process.env.ENV || 'test',
    PORT = parseInt(process.env.PORT || 5000);

var fullMongoUrl = process.env.MONGODB_URI || process.env.MONGOLAB_URI || 'mongodb://localhost:27017/dpd-passport';

console.log('connecting to mongodb', fullMongoUrl);
var server = deployd({
  port: PORT,
  env: ENV,
  db: {
    connectionString: fullMongoUrl
  },
  server_dir: __dirname+'/'
});

server.listen();

server.on('listening', function() {
  console.log("Server is listening", PORT, ENV);
});

server.on('error', function(err) {
  console.error(err);
  process.nextTick(function() { // Give the server a chance to return an error
    process.exit();
  });
});


server.address = function() {
  return {
    port: PORT
  };
};
module.exports = server;