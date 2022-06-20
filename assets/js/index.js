var process = require('process')
var pug = require('pug')
var path = require('path')
var fs = require('fs')
var $ = require('jquery')
const { ipcRenderer } = require('electron')

const PCAPNGParser = require('pcap-ng-parser')
const pcapNgParser = new PCAPNGParser()

const pugMixins = {
	child: pug.compileFile(
		path.join(process.cwd(), 'assets/pug/templates/child.pug')
	),
	bigchilddata: pug.compileFile(
		path.join(process.cwd(), 'assets/pug/templates/bigchilddata.pug')
	),
}

var screen = 1

console.log($)
$(document).ready(() => {
	$('#loadFile').on('click', () => {
		var path = ipcRenderer.sendSync('dialog')
		console.log(path)
		if (path == undefined) {
			notification('Вы не указали путь.')
		} else {
			if (fs.existsSync(path[0])) {
				fileChoosen(path[0])
			} else {
				alert('Ошибка в указанном пути')
			}
		}
	})
})

function toggleAnotherScreen() {
	if (screen == 1) {
		$('#buttonBody').hide()
		$('#infoBody').show()
		screen = 2
		return
	}
	$('#infoBody').hide()
	$('#buttonBody').show()
	screen = 1
}

function parseDataAndAppend(packet) {
	$('#infoBody').append(pug.render('.packet'))
	for (var k of Object.keys(packet)) {
		if (typeof packet[k] == 'object') {
			$('.packet').last().append(pug.render('.bigChild'))
			$('.bigChild')
				.last()
				.append(pugMixins.bigchilddata({ d: k }))
			for (var kk of Object.keys(packet[k])) {
				$('.bigChild')
					.last()
					.append(pugMixins.child({ k: kk, v: packet[k][kk] }))
			}
		} else {
			$('.packet')
				.last()
				.append(pugMixins.child({ k: k, v: packet[k] }))
		}
	}
}

function fileChoosen(filepath) {
	toggleAnotherScreen()
	const myFileStream = fs.createReadStream(filepath)

	myFileStream
		.pipe(pcapNgParser)
		.on('data', (parsedPacket) => {
			var returned = ipcRenderer.sendSync('packet', parsedPacket)
			parseDataAndAppend(returned)
		})
		.on('interface', (interfaceInfo) => {
			console.log(interfaceInfo)
		})
}
