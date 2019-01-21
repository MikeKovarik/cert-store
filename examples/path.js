//var certstore = require('cert-store')
var certstore = require('../index.js')


main().catch(console.error)

async function main() {

	var certPath = './testcert.crt'

	var installed = await certstore.isInstalled(certPath)
	console.log('isInstalled()', installed)

	if (!installed) {

		console.log('installing')
		await certstore.install(certPath)
		console.log('installed')

		installed = await certstore.isInstalled(certPath)
		console.log('isInstalled()', installed)

	}

	console.log('deleting')
	await certstore.delete(certPath)
	console.log('deleted')

	installed = await certstore.isInstalled(certPath)
	console.log('isInstalled()', installed)

}
