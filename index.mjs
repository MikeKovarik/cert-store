import forge from 'node-forge'
import path from 'path'
import cp from 'child_process'
import os from 'os'
import util from 'util'
import _fs from 'fs'
import sudo from 'sudo-prompt'

const __dirname = path.dirname(new URL(import.meta.url).pathname);


var exec = util.promisify(cp.exec)

// not using fs.promise because we're supporting Node 8.
var fs = {}
for (let [name, method] of Object.entries(_fs)) {
	if (typeof method === 'function')
		fs[name] = util.promisify(method)
}

async function ensureDirectory(directory) {
	try {
		await fs.stat(directory)
	} catch(err) {
		await fs.mkdir(directory)
	}
}

// accepts PEM string, removes the --- header/footer, and calculates sha1 hash/thumbprint/fingerprint
function pemToHash(pem) {
	return pem.toString()
	.replace('-----BEGIN CERTIFICATE-----', '')
	.replace('-----END CERTIFICATE-----', '')
	.replace(/\r+/g, '')
	.replace(/\n+/g, '')
	.trim()
}

function isNodeForgeCert(arg) {
	if (typeof arg !== 'object') return false
	return arg.version !== undefined
		&& arg.serialNumber !== undefined
		&& arg.signature !== undefined
		&& arg.publicKey !== undefined
}

const LINUX_CERT_DIR = '/usr/share/ca-certificates/extra/'
// Not tested. I don't have a mac. help needed.
var MAC_DIR
if (os.platform() === 'darwin') {
    let [major, minor] = os.release().split('.').map(Number)
    // if (major >= 10 || minor >= 14)
    MAC_DIR = '/Library/Keychains/System.keychain' // works on major: 16, minor: 7
    // MAC_DIR = '/System/Library/Keychains/SystemRootCertificates.keychain'
}

class CertStruct {

	constructor(arg) {
		if (Buffer.isBuffer(arg))
			arg = arg.toString()
		if (typeof arg === 'string') {
			if (arg.includes('-----BEGIN CERTIFICATE-----'))
				this.pem = arg
			else
				this.path = arg
		} else if (typeof arg === 'object') {
			this.path = arg.path || arg.path
			this.serialNumber = arg.serialNumber
			if (isNodeForgeCert(arg))
				this.pem = forge.pki.certificateToPem(arg)
			else
				this.pem = arg.pem || arg.cert || arg.data
		}
	}

	async ensureCertReadFromFs() {
		if (this.pem) return
		if (!this.path) return
		this.pem = (await fs.readFile(this.path)).toString()
	}

	get name() {
		if (this._name) return this._name
		if (this.path) {
			this._name = path.basename(this.path)
			if (this._name.endsWith('.crt') && this._name.endsWith('.cer'))
				this._name = this._name.slice(0, -4)
			else if (this._name.endsWith('.pem'))
				this._name = this._name.slice(0, -5)
		} else if (this.certificate) {
			let attributes = certificate.subject.attributes
			if (attributes) {
				var obj = attributes.find(obj => obj.shortName === 'CN')
						|| attributes.find(obj => obj.shortName === 'O')
				if (obj)
					this._name = obj.value.toLowerCase().replace(/\W+/g, '-')
			}
		}
		return this._name
	}

	get certificate() {
		if (this._certificate) return this._certificate
		if (this.pem) return this._certificate = forge.pki.certificateFromPem(this.pem)
	}
	set certificate(object) {
		this._certificate = object
	}

	get serialNumber() {
		if (this._serialNumber) return this._serialNumber
		if (this.certificate) return this._serialNumber = this.certificate.serialNumber
	}
	set serialNumber(string) {
		this._serialNumber = string
	}

}

// https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html
class CertStore {

	// Only works on linux (ubuntu, debian).
	// Finds certificate in /usr/share/ca-certificates/extra/ by its serial number.
	// Returns path to the certificate if found, otherwise undefined.
	static async _findLinuxCert(arg) {
		await arg.ensureCertReadFromFs()
		let filenames = await fs.readdir(LINUX_CERT_DIR)
		for (let fileName of filenames) {
			let filepath = LINUX_CERT_DIR + fileName
			let pem = await fs.readFile(filepath)
			let certificate = forge.pki.certificateFromPem(pem)
			if (arg.serialNumber === certificate.serialNumber)
				return filepath
		}
	}

	static async createTempFileIfNeeded(arg) {
		if (arg.path) return
		arg.tempPath = `temp-${Date.now()}-${Math.random()}.crt`
		await fs.writeFile(arg.tempPath, arg.pem)
	}

	static async deleteTempFileIfNeeded(arg) {
		if (!arg.tempPath) return
		await fs.unlink(arg.tempPath)
	}

	// SUGARY METHODS

	static async install(arg) {
		arg = new CertStruct(arg)
		if (!arg.path && !arg.pem)
			throw new Error('path to or contents of the certificate has to be defined.')
		try {
			return await this._install(arg)
		} catch(err) {
			throw new Error(`Couldn't install certificate.\n${err.stack}`)
		} finally {
			this.deleteTempFileIfNeeded(arg)
		}
	}

	static async delete(arg) {
		arg = new CertStruct(arg)
		try {
			return await this._delete(arg)
		} catch(err) {
			throw new Error(`Couldn't delete certificate.\n${err.stack}`)
		}
	}

	static async isInstalled(arg) {
		arg = new CertStruct(arg)
		try {
			return await this._isInstalled(arg)
		} catch(err) {
			throw new Error(`Couldn't find if certificate is installed.\n${err.stack}`)
		}
	}

}


class WindowsCertStore extends CertStore {

	static async _install(arg) {
		await this.createTempFileIfNeeded(arg)
		await exec(`certutil -addstore -user -f root "${arg.path || arg.tempPath}"`)
	}

	static async _delete(arg) {
		await arg.ensureCertReadFromFs()
		await exec(`certutil -delstore -user root ${arg.serialNumber}`)
	}

	static async _isInstalled(arg) {
		await arg.ensureCertReadFromFs()
		try {
			await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
			return true
		} catch(err) {
			// certutil always fails if the serial number is not found.
			return false
		}
	}

}


class LinuxCertStore extends CertStore {

	static async _install(arg) {
		await ensureDirectory(LINUX_CERT_DIR)
		var targetPath = LINUX_CERT_DIR + arg.name + '.crt'
		if (!arg.pem && arg.path)
			arg.pem = await fs.readFile(arg.path)
		await fs.writeFile(targetPath, arg.pem)
		await exec('update-ca-certificates')
	}

	static async _delete(arg) {
		var targetPath = await this._findLinuxCert(arg)
		if (targetPath) await fs.unlink(targetPath)
	}

	static async _isInstalled(arg) {
		return !!(await this._findLinuxCert(arg))
	}

}


// Not tested. I don't have a mac. help needed.
class MacCertStore extends CertStore {

	static async _install(arg) {
		await this.createTempFileIfNeeded(arg)
		const certPath = path.join(__dirname, arg.tempPath)
		const cmd = `security add-trusted-cert -d -k "${MAC_DIR}" "${certPath}"`

		await new Promise((resolve, reject) => {
			sudo.exec(cmd, err => err ? reject(err) : resolve() )
		})
	}

	static async _delete(arg) {
		await arg.ensureCertReadFromFs()
		var fingerPrint = forge.md.sha1.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(arg.certificate)).getBytes()).digest().toHex()

		const cmd = `security delete-certificate -Z ${fingerPrint} "${MAC_DIR}"`
		await new Promise((resolve, reject) => {
			sudo.exec(cmd, err => err ? reject(err) : resolve())
		})
	}

	static async _isInstalled(arg) {
		const allCerts = await exec(`security  find-certificate -a -p`)
		const pem = arg.pem.replace(/\r/g, '')
		return allCerts.stdout.includes(pem)
	}

}


var PlatformSpecificCertStore

switch (process.platform) {
    case 'win32':
        PlatformSpecificCertStore = WindowsCertStore
        break
    case 'darwin':
        PlatformSpecificCertStore = MacCertStore
        break
    default:
        PlatformSpecificCertStore = LinuxCertStore
        break
}

export default PlatformSpecificCertStore