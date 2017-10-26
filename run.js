var mpass = require('./masterpass');

const express = require('express');
const app = express();



var params = {
            currency: "BRL",
            amount: 100,
            paymentSuccessful: true,
			paymentCode: "123456", //from the gateway/acquirer - six digit code
            paymentDate: Math.floor(new Date() / 1000)
        };


app.get('/callback-standard', function(req, res) {
	
	var masterpass = new mpass.Masterpass({
    	p12: './sandbox.p12',
    	password: 'wDWmmgi3AY0L5qwolJXw',
	    consumerKey: 'x9CN7cXABdzeOpjVrAOa7v4pHhpkzLNTDcMEIOY60e2a0e46!10e8bc47714141be983e984732a73a4c0000000000000000',
	    cartId: '123456',
	    checkoutId: 'd072ca48e19b49c49bb76ea4513b42d1',
	    transactionId: req.query.oauth_token
	});
	
	
	// paymentdata
	masterpass.paymentdata(function(success, data){
	

		if(success)		
		{	
			console.log("paymentdata = ok");
			
			masterpass.postback(params, function(success, data){
				
				if(success)	{
					res.send(jsona + "<Br>" + jsonb);
					console.log("postback = ok");
				}
				else
					res.send("Erro " + data);
					
			});
		}
		else
		{
			res.send("Erro " + data);
		}
		
	});
	


});

app.use(express.static('public'));


app.listen(4567, function() {
	console.log('listening on 4567');
});