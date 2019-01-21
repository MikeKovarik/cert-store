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


const LINUX_CERT_DIR = '/usr/share/ca-certificates/extra/'

function isNodeForgeCert(arg) {
	if (typeof arg !== 'object') return false
	return arg.version !== undefined
		&& arg.serialNumber !== undefined
		&& arg.signature !== undefined
		&& arg.publicKey !== undefined
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

	static async install(arg) {
		arg = new CertStruct(arg)
		if (!arg.path && !arg.pem)
			throw new Error('path to or contents of the certificate has to be defined.')
		try {
			switch (process.platform) {
				case 'win32':
					if (arg.path) {
						await exec(`certutil -addstore -user -f root "${arg.path}"`)
					} else if (arg.pem) {
						var tempPath = `temp-${Date.now()}-${Math.random()}.crt`
						await fs.writeFile(tempPath, arg.pem)
						try {
							await exec(`certutil -addstore -user -f root "${tempPath}"`)
						} catch(err) {
							await fs.unlink(tempPath)
							throw err
						}
					}
					return
				case 'darwin':
					// TODO
					throw new Error('install() not yet implemented on this platform')
				default:
					await ensureDirectory(LINUX_CERT_DIR)
					var targetPath = LINUX_CERT_DIR + arg.name + '.crt'
					if (!arg.pem && arg.path)
						arg.pem = await fs.readFile(arg.path)
					await fs.writeFile(targetPath, arg.pem)
					await exec('update-ca-certificates')
					return
			}
		} catch(err) {
			throw new Error(`Couldn't install certificate.\n${err.stack}`)
		}
	}

	static async isInstalled(arg) {
		arg = new CertStruct(arg)
		switch (process.platform) {
			case 'win32':
				await arg.ensureCertReadFromFs()
				try {
					await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
					return true
				} catch(err) {
					// certutil always fails if the serial number is not found.
					return false
				}
			case 'darwin':
				// TODO
				throw new Error('isInstalled() not yet implemented on this platform')
			default:
				return !!(await this._findLinuxCert(arg))
		}
	}

	static async delete(arg) {
		arg = new CertStruct(arg)
		switch (process.platform) {
			case 'win32':
				await arg.ensureCertReadFromFs()
				await exec(`certutil -delstore -user root ${arg.serialNumber}`)
				return
			case 'darwin':
				// TODO
				throw new Error('delete() not yet implemented on this platform')
			default:
				var targetPath = await this._findLinuxCert(arg)
				if (targetPath) await fs.unlink(targetPath)
				return
		}
	}

}