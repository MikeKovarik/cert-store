# cert-store

🔑

## Installation

```js
npm install cert-store
```

## Usage

Using path to `.crt`, `.cert`, or `.pem` file.

```js
import certstore from 'cert-store'

var certPath = './testsrv.root-ca.crt'
// installing certificate
await certstore.install(certPath)
// checking if cert is already installed
console.log('installed', await certstore.isInstalled(certPath))
// deleting certificate
await certstore.delete(certPath)
```

Using pem string.

```js
import certstore from 'cert-store'

var pem = `
`

// Install certificate from pem string.
await certstore.install(pem)
// Check for existence or delete (uses certificate's serial number).
var installed = await certstore.isInstalled(pem)
await certstore.delete(pem)
```

Using node-forge object.

```js
import forge from 'node-forge'
import certstore from 'cert-store'

// Create your cert with node-forge.
// WARNING: this is incomplete example, look at node-forge's readme for more info.
var keys = pki.rsa.generateKeyPair(2048)
var cert = pki.createCertificate()
cert.publicKey = keys.publicKey
// certificate has to have UNIQUE serialNumber.
cert.serialNumber = '0123456789'
cert.validity.notBefore = new Date()
cert.validity.notAfter = new Date()
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
cert.setSubject(...)
cert.setIssuer(...)
...
cert.sign(keys.privateKey)

// use the cert object as argument.
await certstore.install(cert)
```


## License

MIT, Mike Kovařík, Mutiny.cz