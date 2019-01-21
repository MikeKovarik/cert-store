var forge = require('node-forge')
var {createRootCa} = require('selfsigned-ca')
//var certstore = require('cert-store')
var certstore = require('../index.js')


// selfsigned-ca internally calls node-forge to create CA certificate.
// It also adds proper attributes, extensions and serial number so that chrome
// doesn't reject the cert from https servers. 
// The returned object is straight from node-forge. Such as:
// var certificate = forge.pki.createCertificate()
var {certificate} = createRootCa('My Trusted Certificate Authority')
var pem = forge.pki.certificateToPem(certificate)

certstore.install(certificate)
	.then(() => console.log('installed node-forge certificate object'))
	.catch(err => console.error(err))
