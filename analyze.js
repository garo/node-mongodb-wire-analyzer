var pcap = require('pcap');
var BSON = require('bson').pure().BSON;
var argv = require('optimist').argv;
var StatsD = require('statsd-client');

function help() {
  process.stderr.write("Usage: node ./analyze.js --interface <interface name from ifconfig>\n");
  process.stderr.write("Optional arguments:\n\n");
  process.stderr.write("\t--stdout\n");
  process.stderr.write("\t\tPrint query data to stdout (in ugly json)\n");
  process.stderr.write("\n");
  process.stderr.write("\t--filter <tcpdump filter>\n");
  process.stderr.write("\t\tDefault filter string is \"dst port 27017\"\n");
  process.stderr.write("\n");
  process.stderr.write("\t--statsd <host>\n");
  process.stderr.write("\t\tSends update/insert/query statistics to statsd/graphite server.\n");
  process.stderr.write("\t--statsd-port <port>\n");
  process.stderr.write("\t\tSets statsd port. default port is 8125.\n");
  process.stderr.write("\n");
  process.stderr.write("\t--statsd-prefix <prefix name>\n");
  process.stderr.write("\t\tPrefix for statsd. Default prefix is \"mongodb.wirestats\"\n");
  process.stderr.write("\n");
  process.stderr.write("Issues, feedback etc at https://github.com/garo/node-mongodb-wire-analyzer");
  process.stderr.write("\n");

  process.exit();
}

var interface = argv.interface || help();
var filter = argv.filter || "dst port 27017";

var statsd = null;
if (argv.statsd) {
  statsd = new StatsD({host: argv.statsd, port: Number(argv["statsd-port"] || 8125), prefix : argv["statsd-prefix"] || "mongodb.wirestats"});
}

var pcap_session = pcap.createSession(interface, filter);

pcap_session.on('packet', function (raw_packet) {
  var packet = pcap.decode.packet(raw_packet);
  if (packet.link.pftype == 2 && packet.link.ip.version == 4 && packet.link.ip.protocol_name == 'TCP') {
    if (packet.link.ip.tcp.data) {
      parseMongoDbData(packet.link.ip.tcp.data);
    }

  }
});

/**
 * Parses mongodb request from the buffer containing TCP payload.
 *
 * The buffer doesn't have to be a complete TCP stream, but the payload from the first packet usually is enough
 *
 * This function has a few internal functions which read parts of the Buffer. They all rely heavily on the 'offset'
 * variable, which stores the state and position of the first unread byte in the Buffer.
 *
 * The readBSON relies on the fact that the first four bytes of the BSON message contains the lengt of the message
 * in sint32. This length is used to feed a sliced buffer to the BSON deserializer.
 *
 * MongoDB wire protocol spec at http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/
 * @param buffer
 */
function parseMongoDbData(buffer) {
  var offset = 0;
  var msgHeader = readMsgHeader(buffer);

  switch (msgHeader.opCode) {
    case 2001: // OP_UPDATE
      var updateQuery = readUpdateQuery();
      argv.stdout && console.log("updateQuery", updateQuery);
      statsd && statsd.increment('update.' + updateQuery.fullCollectionName);

      break;
    case 2002: // OP_INSERT
      var insertQuery = readInsertQuery();
      argv.stdout && console.log("insertQuery", insertQuery);
      statsd && statsd.increment('insert.' + insertQuery.fullCollectionName);
      break;

    case 2004: // OP_QUERY
      var opQuery = readOpQuery();
      statsd && statsd.increment('query.' + opQuery.fullCollectionName);
      argv.stdout && console.log("opQuery:", opQuery);
      break;

    default:
      argv.stdout && console.log("Unknown opCode", msgHeader.opCode);
  }

  function readMsgHeader() {
    /* struct MsgHeader {
     int32   messageLength; // total message size, including this
     int32   requestID;     // identifier for this message
     int32   responseTo;    // requestID from the original request
     //   (used in reponses from db)
     int32   opCode;        // request type - see table below
     }
     */
    var msgHeader = {};
    msgHeader.messageLength = buffer.readUInt32LE(offset);
    msgHeader.requestID = buffer.readUInt32LE(offset + 4);
    msgHeader.responseTo = buffer.readUInt32LE(offset + 8);
    msgHeader.opCode = buffer.readUInt32LE(offset + 12);
    offset += 16;

    return msgHeader;
  }

  function readUpdateQuery() {
    /* struct OP_UPDATE {
        MsgHeader header;             // standard message header
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     flags;              // bit vector. see below
        document  selector;           // the query to select the document
        document  update;             // specification of the update to perform
    }
    */

    var updateQuery = {};
    offset += 4; // read the ZERO out

    updateQuery.fullCollectionName = readCString(buffer);
    updateQuery.flags = readuint32(offset);
    updateQuery.selector = readBSON();
    updateQuery.update = readBSON();


    return updateQuery;
  }

  function readInsertQuery() {
    /* struct {
        MsgHeader header;             // standard message header
        int32     flags;              // bit vector - see below
        cstring   fullCollectionName; // "dbname.collectionname"
        document* documents;          // one or more documents to insert into the collection
    }

    */

    var insertQuery = {};
    insertQuery.flags = readuint32(offset);
    insertQuery.fullCollectionName = readCString(buffer);
    insertQuery.documents = [];
    do {
      insertQuery.documents.push(readBSON());
    } while (offset < buffer.length);

    return insertQuery;
  }

  function readOpQuery() {
    /* struct OP_QUERY {
     MsgHeader header;                 // standard message header
     int32     flags;                  // bit vector of query options.  See below for details.
     cstring   fullCollectionName ;    // "dbname.collectionname"
     int32     numberToSkip;           // number of documents to skip
     int32     numberToReturn;         // number of documents to return
     //  in the first OP_REPLY batch
     document  query;                  // query object.  See below for details.
     [ document  returnFieldsSelector; ] // Optional. Selector indicating the fields
     //  to return.  See below for details.
     }
     */
    var opQuery = {};
    opQuery.flags = readuint32(offset);
    opQuery.fullCollectionName = readCString();
    opQuery.numberToSkip = readuint32(offset);
    opQuery.numberToReturn = readuint32(offset);
    opQuery.query = readBSON();

    return opQuery;
  }

  function readCString() {
    var cstring = "";
    var c = null;
    do {
      c = buffer.readUInt8(offset);
      offset++;

      if (c == 0) {
        break;
      }
      cstring += String.fromCharCode(c);
    } while (offset < buffer.length);

    return cstring.toString();
  }

  function readuint32() {
    var c = buffer.readUInt32LE(offset);
    offset += 4;
    return c;
  }

  function readBSON() {
    // BSON binary format spec from http://bsonspec.org/#/specification

    // Peek the length, but don't move the offset because BSON deserializer wants also to have the length
    var len = buffer.readInt32LE(offset);

    // Check if the buffer is too small to contain the full message
    if (buffer.length < len + offset) {
      return null;
    }

    var bsonbuf = buffer.slice(offset, offset + len);
    offset += len;

    return BSON.deserialize(bsonbuf);

  }

}

