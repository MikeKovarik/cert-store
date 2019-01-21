import forge from 'node-forge'
import path from 'path'
import cp from 'child_process'
import util from 'util'
import _fs from 'fs'


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
	.replace(BEGIN, '')
	.replace(END, '')
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
const MAC_DIR = '/System/Library/Keychains/SystemRootCertificates.keychain'
//const MAC_DIR = '/Library/Keychains/System.keychain'

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
export default class CertStore {

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
			switch (process.platform) {
				case 'win32':	return await this.installWindows(arg)
				case 'darwin':	return await this.installMac(arg)
				default:		return await this.installLinux(arg)
			}
		} catch(err) {
			throw new Error(`Couldn't install certificate.\n${err.stack}`)
		} finally {
			this.deleteTempFileIfNeeded(arg)
		}
	}

	static async delete(arg) {
		arg = new CertStruct(arg)
		try {
			switch (process.platform) {
				case 'win32':	return await this.deleteWindows(arg)
				case 'darwin':	return await this.deleteMac(arg)
				default:		return await this.deleteLinux(arg)
			}
		} catch(err) {
			throw new Error(`Couldn't delete certificate.\n${err.stack}`)
		}
	}

	static async isInstalled(arg) {
		arg = new CertStruct(arg)
		try {
			switch (process.platform) {
				case 'win32':	return await this.isInstalledWindows(arg)
				case 'darwin':	return await this.isInstalledMac(arg)
				default:		return await this.isInstalledLinux(arg)
			}
		} catch(err) {
			throw new Error(`Couldn't find if certificate is installed.\n${err.stack}`)
		}
	}

	// WINDOWS

	static async installWindows(arg) {
		await this.createTempFileIfNeeded(arg)
		await exec(`certutil -addstore -user -f root "${arg.path || arg.tempPath}"`)
	}

	static async deleteWindows(arg) {
		await arg.ensureCertReadFromFs()
		await exec(`certutil -delstore -user root ${arg.serialNumber}`)
	}

	static async isInstalledWindows(arg) {
		await arg.ensureCertReadFromFs()
		try {
			await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
			return true
		} catch(err) {
			// certutil always fails if the serial number is not found.
			return false
		}
	}

	// LINUX

	static async installLinux(arg) {
		await ensureDirectory(LINUX_CERT_DIR)
		var targetPath = LINUX_CERT_DIR + arg.name + '.crt'
		if (!arg.pem && arg.path)
			arg.pem = await fs.readFile(arg.path)
		await fs.writeFile(targetPath, arg.pem)
		await exec('update-ca-certificates')
	}

	static async deleteLinux(arg) {
		var targetPath = await this._findLinuxCert(arg)
		if (targetPath) await fs.unlink(targetPath)
	}

	static async isInstalledLinux(arg) {
		return !!(await this._findLinuxCert(arg))
	}

	// MAC

	static async installMac(arg) {
		await this.createTempFileIfNeeded(arg)
		await exec(`security add-trusted-cert -d -r trustRoot -k "${MAC_DIR}" "${arg.path}"`)
	}

	static async deleteMac(arg) {
		await arg.ensureCertReadFromFs()
		var fingerPrint = pemToHash(arg.pem)
		await exec(`security delete-certificate -Z ${fingerPrint} "${MAC_DIR}"`)
	}

	static async isInstalledMac(arg) {
		// TODO
		throw new Error('isInstalled() not yet implemented on this platform')
	}

}