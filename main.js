const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const decoders = require('cap').decoders
const PROTOCOL = decoders.PROTOCOL
const locals = {
	/* ...*/
}
const setupPug = require('electron-pug')

const createWindow = async () => {
	try {
		let pug = await setupPug({ pretty: true }, locals)
		pug.on('error', (err) => console.error('electron-pug error', err))
	} catch (err) {
		// Could not initiate 'electron-pug'
	}
	const win = new BrowserWindow({
		width: 800,
		height: 600,
		webPreferences: {
			nodeIntegration: true,
			contextIsolation: false,
		},
	})
	// win.webContents.openDevTools()
	win.removeMenu()

	win.loadURL(`file://${__dirname}/assets/pug/views/index.pug`)
}

app.whenReady().then(() => {
	try {
		// require('electron-reloader')(module)
	} catch (_) {}
	createWindow()
})

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') app.quit()
})

ipcMain.on('packet', (event, packet) => {
	var buffer = new Buffer.from(packet.data, 'utf-8')
	// console.log(packet)
	var array = packet.data

	var ret1 = decoders.Ethernet(buffer)

	var packetInfo = {
		interfaceId: packet.interfaceId,
		dstmac: ret1.info.dstmac,
		srcmac: ret1.info.srcmac,
	}

	if (ret1.info.type === PROTOCOL.ETHERNET.IPV4) {
		// console.log('Decoding IPv4 ...')

		var ret2 = decoders.IPV4(buffer, ret1.offset)
		packetInfo.IPV4 = ret2.info

		// console.log('from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr)

		if (ret2.info.protocol === PROTOCOL.IP.TCP) {
			var datalen = ret2.info.totallen - ret2.hdrlen
			var ret3 = decoders.TCP(buffer, ret2.offset)
			datalen -= ret3.hdrlen

			packetInfo.TCP = ret3.info
			packetInfo.TCP.datalength = datalen
			packetInfo.TCP.data = buffer.toString(
				'binary',
				ret3.offset,
				ret3.offset + datalen
			)
		} else if (ret2.info.protocol === PROTOCOL.IP.UDP) {
			var ret3 = decoders.UDP(buffer, ret2.offset)

			packetInfo.UDP = ret3.info
			packetInfo.UDP.data = buffer.toString(
				'binary',
				ret3.offset,
				ret3.offset + ret3.info.length
			)
		} else
			console.log(
				'Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret2.info.protocol]
			)
	}

	event.returnValue = packetInfo
})
ipcMain.on('dialog', (event) => {
	event.returnValue = dialog.showOpenDialogSync({
		properties: ['openFile'],
		filters: [{ name: 'pcapng файлы', extensions: ['pcapng'] }],
	})
})
