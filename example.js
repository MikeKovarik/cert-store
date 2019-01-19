//var {Cert} = require('selfsigned-ca')
var {CertStore} = require('./index.js')


main().catch(console.error)

async function main() {

	var certPath = './testsrv.root-ca.crt'

	var installed = await CertStore.isInstalled(certPath)
	console.log('isInstalled()', installed)

	if (!installed) {

		console.log('installing')
		await CertStore.install(certPath)
		console.log('installed')

		installed = await CertStore.isInstalled(certPath)
		console.log('isInstalled()', installed)

	}

	console.log('deleting')
	await CertStore.delete(certPath)
	console.log('deleted')

	installed = await CertStore.isInstalled(certPath)
	console.log('isInstalled()', installed)


}
