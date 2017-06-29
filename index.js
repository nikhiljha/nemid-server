var express = require('express')
var app = express();
const uuidV1 = require('uuid/v1');
var levelup = require('levelup');
var db = levelup('./sessions');
var nem = require("nem-sdk").default;
var nacl = require("tweetnacl");

const _hexEncodeArray = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

/**
* Reversed convertion of hex to Uint8Array
*
* @param {string} hexx - An hex string
*
* @return {Uint8Array}
*/
let hex2ua_reversed = function(hexx) {
    let hex = hexx.toString(); //force conversion
    let ua = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        ua[ua.length - 1 - (i / 2)] = parseInt(hex.substr(i, 2), 16);
    }
    return ua;
};

/**
* Convert hex to Uint8Array
*
* @param {string} hexx - An hex string
*
* @return {Uint8Array}
*/
let hex2ua = function(hexx) {
    let hex = hexx.toString(); //force conversion
    let ua = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        ua[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return ua;
};

/**
* Convert an Uint8Array to hex
*
* @param {Uint8Array} ua - An Uint8Array
*
* @return {string}
*/
let ua2hex = function(ua) {
    let s = '';
    for (let i = 0; i < ua.length; i++) {
        let code = ua[i];
        s += _hexEncodeArray[code >>> 4];
        s += _hexEncodeArray[code & 0x0F];
    }
    return s;
};

/**
* Convert hex to string
*
* @param {string} hexx - An hex string
*
* @return {string}
*/
let hex2a = function(hexx) {
    let hex = hexx.toString();
    let str = '';
    for (let i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
};

/**
* Convert UTF-8 to hex
*
* @param {string} str - An UTF-8 string
*
* @return {string}
*/
let utf8ToHex = function(str) {
    let rawString = rstr2utf8(str);
    let hex = "";
    for (var i = 0; i < rawString.length; i++) {
        hex += strlpad(rawString.charCodeAt(i).toString(16), "0", 2)
    }
    return hex;
};

// Padding helper for above function
let strlpad = function(str, pad, len) {
    while (str.length < len) {
        str = pad + str;
    }
    return str;
}

/**
* Convert an Uint8Array to WordArray
*
* @param {Uint8Array} ua - An Uint8Array
* @param {number} uaLength - The Uint8Array length
*
* @return {WordArray}
*/
let ua2words = function(ua, uaLength) {
    let temp = [];
    for (let i = 0; i < uaLength; i += 4) {
        let x = ua[i] * 0x1000000 + (ua[i + 1] || 0) * 0x10000 + (ua[i + 2] || 0) * 0x100 + (ua[i + 3] || 0);
        temp.push((x > 0x7fffffff) ? x - 0x100000000 : x);
    }
    return CryptoJS.lib.WordArray.create(temp, uaLength);
}

/**
* Convert a wordArray to Uint8Array
*
* @param {Uint8Array} destUa - A destination Uint8Array
* @param {WordArray} cryptowords - A wordArray
*
* @return {Uint8Array}
*/
let words2ua = function(destUa, cryptowords) {
    for (let i = 0; i < destUa.length; i += 4) {
        let v = cryptowords.words[i / 4];
        if (v < 0) v += 0x100000000;
        destUa[i] = (v >>> 24);
        destUa[i + 1] = (v >>> 16) & 0xff;
        destUa[i + 2] = (v >>> 8) & 0xff;
        destUa[i + 3] = v & 0xff;
    }
    return destUa;
}

/**
* Converts a raw javascript string into a string of single byte characters using utf8 encoding.
* This makes it easier to perform other encoding operations on the string.
*
* @param {string} input - A raw string
*
* @return {string} - UTF-8 string
*/
let rstr2utf8 = function (input) {
    let output = "";

    for (let n = 0; n < input.length; n++) {
        let c = input.charCodeAt(n);

        if (c < 128) {
            output += String.fromCharCode(c);
        } else if ((c > 127) && (c < 2048)) {
            output += String.fromCharCode((c >> 6) | 192);
            output += String.fromCharCode((c & 63) | 128);
        } else {
            output += String.fromCharCode((c >> 12) | 224);
            output += String.fromCharCode(((c >> 6) & 63) | 128);
            output += String.fromCharCode((c & 63) | 128);
        }
    }

    return output;
}

// Does the reverse of rstr2utf8.
let utf82rstr = function (input) {
    let output = "", i = 0, c = 0, c1 = 0, c2 = 0, c3 = 0;

    while (i < input.length) {
        c = input.charCodeAt(i);

        if (c < 128) {
            output += String.fromCharCode(c);
            i++;
        } else if ((c > 191) && (c < 224)) {
            c2 = input.charCodeAt(i + 1);
            output += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
            i += 2;
        } else {
            c2 = input.charCodeAt(i + 1);
            c3 = input.charCodeAt(i + 2);
            output += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
            i += 3;
        }
    }

    return output;
}

// Server Routes
app.get('/', function (req, res) {
	var uuid = uuidV1();
	res.send('<a href="nemid://' + uuid + '/localhost/callback' + '">Sign In</a>');
	db.put(uuid, true, function (err) {
	  if (err) return console.log('ERR: IO!', err) // some kind of I/O error
	})
})

var keyPair = nem.crypto.keyPair.create(nem.utils.convert.ua2hex(nem.crypto.nacl.randomBytes(32)));

app.get('/callback', function (req, res) {
	var uuid = req.query.uuid;
	var sig = req.query.sig;
	var pub = req.query.pub;
	db.get(uuid, function (err, value) {
		if (err) {
			res.send("Could not find your signin attempt.");
		} else {
			if(nem.crypto.verifySignature(pub, "nemid://" + uuid + "/localhost/callback", sig)) {
				res.send("Logged in successfully as " + nem.model.address.toAddress(pub, 104));
			} else {
				res.send("Bad login!")
			}
		}
  })
})

app.listen(80, function () {
  console.log('The server is now running on port 80. Visit localhost:80 to test it out!')
})