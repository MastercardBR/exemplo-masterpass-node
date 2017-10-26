var fs = require('fs');
var util = require('util')
var crypto = require('crypto');
var async = require('async');
var merge = require('merge');
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const request = require('request'), querystring = require('querystring');


function Masterpass(opts) 
{

    this.conf = merge({
        version: '1.0',
        signature: 'RSA-SHA256',
        realm: 'eWallet',
        env: 'stage',
        urlPrefix: 'https://sandbox.api.mastercard.com',
        keySize: 2048
    }, opts, {
            urls: {
                production: 'https://api.mastercard.com',
                stage: 'https://sandbox.api.mastercard.com',
                paymentdata: '/masterpass/paymentdata/%s?cartId=%s&checkoutId=%s',
                postback: '/masterpass/postback'
            }
        });
        
    if (this.conf.env === 'production') 
    {
        this.conf.urlPrefix = this.conf.urls.production;
    } 
    else 
    {
        this.conf.urlPrefix = this.conf.urls.stage;
    }
    
    this.conf.paymentdataUrl = this.conf.urlPrefix + this.conf.urls.paymentdata;
    this.conf.postbackUrl = this.conf.urlPrefix + this.conf.urls.postback;
    
    if (this.conf.httpProxy && "" !== this.conf.httpProxy) 
    {
        console.log('using proxy', this.conf.httpProxy)
    }

}

Masterpass.prototype._privateKey = function()
{

	var keyFile = fs.readFileSync(this.conf.p12);
	var keyBase64 = keyFile.toString('base64');

	var p12Der = forge.util.decode64(keyBase64);
	var p12Asn1 = forge.asn1.fromDer(p12Der);
	var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, this.conf.password);
	var keyBags = p12.getBags({bagType: forge.pki.oids.pkcs8ShroudedKeyBag});
	var bag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
	var privateKey = bag.key;
	
	var pem = forge.pki.privateKeyToPem(privateKey);
	
	return pem;
	
}

Masterpass.prototype.getTimestamp = function () {
    return "" + Math.floor((new Date()).getTime() / 1000);
};

Masterpass.prototype.getNonce = function () {
    var hrtime = process.hrtime();
    return "" + (hrtime[0] * 1e9 + hrtime[1]);
};


Masterpass.prototype.encodeData = function (toEncode) {
    if (toEncode === null || toEncode === "") {
        return "";
    } else {
        var result = encodeURIComponent(toEncode);
        return result.replace(/\!/g, "%21")
            .replace(/\'/g, "%27")
            .replace(/\(/g, "%28")
            .replace(/\)/g, "%29")
            .replace(/\*/g, "%2A")
            .replace(/\+/g, "%20")
            .replace(/\~/g, "%7E")
            .replace(/\?/g, "%3F")
    }
};

Masterpass.prototype.buildHeaderString = function (ctx, callback) {
    var params = [];
    for (var key in ctx.params) {
        if (ctx.params.hasOwnProperty(key)) {
            params.push(key + "=\"" + this.encodeData(ctx.params[key]) + "\"");
        }
    }
    ctx.headerString = "OAuth " + params.join(",");
    callback(null, ctx);
};

Masterpass.prototype.signHeader = function (ctx, callback) {
    ctx.params.oauth_signature = crypto.createSign("RSA-SHA256").update(ctx.header).sign(this._privateKey(), 'base64');
    callback(null, ctx);
};

Masterpass.prototype.buildRequestHeader = function (ctx, callback, method) {

    var params = {
        oauth_consumer_key: this.conf.consumerKey,
        oauth_nonce: this.getNonce(),
        oauth_timestamp: this.getTimestamp(),
        oauth_signature_method: this.conf.signature,
        oauth_version: this.conf.version
    }; 
    
    
    var customParams = {};
        
    // encoded params
    var encodedParams = [
        "oauth_consumer_key=" + this.encodeData(params.oauth_consumer_key),
        "oauth_nonce=" + this.encodeData(params.oauth_nonce), 
        "oauth_signature_method=" + this.encodeData(params.oauth_signature_method),
        "oauth_timestamp=" + this.encodeData(params.oauth_timestamp), 
        "oauth_version=" + this.encodeData(params.oauth_version)
    ];
    
    
    // action + querystring if available
    var action = ctx.url;
    
    if(action.indexOf("?")>0)
    {
		action = ctx.url.substring(0, ctx.url.indexOf("?") == -1 ? ctx.url.length() : ctx.url.indexOf("?"));
		var qstrparams = ctx.url.substring( ctx.url.indexOf("?")+1, ctx.url.length);
		merge( customParams, querystring.parse( qstrparams ));
				
    }
    
    // encode the custom params
    if (customParams) {	
        for (var key in customParams) {
            if (customParams.hasOwnProperty(key) && key != 'realm') {
                encodedParams.push(key + '=' + this.encodeData(customParams[key]))
            }
        }
    }
    
    // sort as part of oauth spec
    encodedParams = encodedParams.sort();
    
    // calculate body hash if post
    if (ctx.body) {
        var hash = crypto.createHash('sha256');
        hash.update(ctx.body);
        
        var hashed = hash.digest('base64');
        encodedParams.unshift("oauth_body_hash=" + this.encodeData(hashed));
        params.oauth_body_hash = hashed;
    }
    
    ctx.params = params;
    
    ctx.header = [method ? method : "POST", encodeURIComponent(action), encodeURIComponent(encodedParams.join('&'))].join("&");
//    console.log("== base string ==");
    console.log(ctx.header);
    callback(null, ctx);
};

Masterpass.prototype.send = function (ctx, callback, method) {
    var ptr = this;
    var req = {
        uri: ctx.url,
        method: method ? method : 'POST',
        headers: {
            'Authorization': ctx.headerString,
            'Content-Type': 'application/json'
        }
    };
    
    console.log("==header==");
    console.log(ctx.headerString);
    
    if (this.conf.httpProxy && "" !== this.conf.httpProxy) {
        req.proxy = this.conf.httpProxy;
    }
    if (this.conf.hasOwnProperty('rejectUnauthorized')) {
        console.log('rejectUnauthorized');
        req.rejectUnauthorized  = this.conf.rejectUnauthorized ;
    }
    if (ctx.body) {
        req.body = ctx.body;
    }
   
    request(req, function (error, response, body) {
        
		console.log("==result==");
        console.log(response.statusCode);
        console.log(body);
        
        if (error) 
        {
            callback(false, error);
        } 
        else if (200 == response.statusCode || 204 == response.statusCode) 
        {
            console.log("== success ==");
            callback(true, body);
            
        } 
        else 
        {
            callback(false, body);
        }
    });
};

Masterpass.prototype.buildAndSendRequest = function (ctx, callback, method) {
    var ptr = this;
    async.waterfall([
        function (callback) {
            ptr.buildRequestHeader(ctx, callback, method);
        },
        function (ctx, callback) {
            ptr.signHeader(ctx, callback);
        },
        function (ctx, callback) {
            ptr.buildHeaderString(ctx, callback);
        },
        function (ctx, callback) {
            ptr.send(ctx, callback, method);
        }
    ], callback);
};

Masterpass.prototype.paymentdata = function(callback) {

    var ptr = this;
	
	ptr.buildAndSendRequest({
		url: util.format(ptr.conf.paymentdataUrl, ptr.conf.transactionId, ptr.conf.cartId, ptr.conf.checkoutId),
        }, 
        callback, 
        'GET');

};
Masterpass.prototype.postback = function (req, callback) {

    var ptr = this;  
    
    var post = {
            transactionId: ptr.conf.transactionId,
            currency: req.currency,
            amount: req.amount,
            paymentSuccessful: req.paymentSuccessful,
			paymentCode: req.paymentCode,
            paymentDate: req.paymentDate
        };
        
        ptr.buildAndSendRequest({
                url: ptr.conf.postbackUrl,
                body: JSON.stringify(post)
            }, callback, 'POST');
};


module.exports.Masterpass = Masterpass;