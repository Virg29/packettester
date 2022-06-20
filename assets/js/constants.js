var LINKTYPE_ = {
	0: {
		linktype_name: 'LINKTYPE_NULL',
		dlt_name: 'DLT_NULL',
		description_name:
			" BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order, containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23 for IPX packets.All of the IPv6 values correspond to IPv6 packets; code reading files should check for all of them.<p>Note that ``host byte order'' is the byte order of the machine on that the packets are captured; if a live capture is being done, ``host byte order'' is the byte order of the machine capturing the packets, but if a ``savefile'' is being read, the byte order is not necessarily that of the machine reading the capture file.</p>",
	},
	1: {
		linktype_name: 'LINKTYPE_ETHERNET',
		dlt_name: 'DLT_EN10MB',
		description_name:
			' IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical.',
	},
	3: {
		linktype_name: 'LINKTYPE_AX25',
		dlt_name: 'DLT_AX25',
		description_name: ' AX.25 packet, with nothing preceding it.',
	},
	6: {
		linktype_name: 'LINKTYPE_IEEE802_5',
		dlt_name: 'DLT_IEEE802',
		description_name:
			' IEEE 802.5 Token Ring; the IEEE802, without _5, in the DLT_ name is historical.',
	},
	7: {
		linktype_name: 'LINKTYPE_ARCNET_BSD',
		dlt_name: 'DLT_ARCNET',
		description_name:
			' ARCNET Data Packets, as described by the ARCNET Trade Association standard RFC 1201 ; for RFC 1051 frames, ATA 878.2 is not used.',
	},
	8: {
		linktype_name: 'LINKTYPE_SLIP',
		dlt_name: 'DLT_SLIP',
		description_name: ' SLIP, encapsulated with a LINKTYPE_SLIP header .',
	},
	9: {
		linktype_name: 'LINKTYPE_PPP',
		dlt_name: 'DLT_PPP',
		description_name:
			' PPP, as per RFC 1662 ; if the first 2 bytes are 0xff and 0x03, its PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise its PPP without framing, and the packet begins with the PPP header.The data in the frame is not octet-stuffed or bit-stuffed.',
	},
	10: {
		linktype_name: 'LINKTYPE_FDDI',
		dlt_name: 'DLT_FDDI',
		description_name: ' FDDI, as specified by ANSI INCITS 239-1994.',
	},
	50: {
		linktype_name: 'LINKTYPE_PPP_HDLC',
		dlt_name: 'DLT_PPP_SERIAL',
		description_name:
			' PPP in HDLC-like framing, as per  section 4.3.1 of RFC 1547 ; the first byte will be 0xFF for PPP in HDLC-like framing, and will be 0x0F or 0x8F for Cisco PPP with HDLC framing.The data in the frame is not octet-stuffed or bit-stuffed.',
	},
	51: {
		linktype_name: 'LINKTYPE_PPP_ETHER',
		dlt_name: 'DLT_PPP_ETHER',
		description_name:
			' PPPoE; the packet begins with a PPPoE header, as per RFC 2516 .',
	},
	100: {
		linktype_name: 'LINKTYPE_ATM_RFC1483',
		dlt_name: 'DLT_ATM_RFC1483',
		description_name:
			' ISO 8802-2 (formerly known as IEEE 802.2) LLC header.',
	},
	101: {
		linktype_name: 'LINKTYPE_RAW',
		dlt_name: 'DLT_RAW',
		description_name:
			" Raw IP; the packet begins with an IPv4 or IPv6 header, with the version field of the header indicating whether it's an IPv4 or IPv6 header.",
	},
	104: {
		linktype_name: 'LINKTYPE_C_HDLC',
		dlt_name: 'DLT_C_HDLC',
		description_name:
			' Cisco PPP with HDLC framing, as per  section 4.3.1 of RFC 1547 .',
	},
	105: {
		linktype_name: 'LINKTYPE_IEEE802_11',
		dlt_name: 'DLT_IEEE802_11',
		description_name: ' IEEE 802.11 wireless LAN.',
	},
	107: {
		linktype_name: 'LINKTYPE_FRELAY',
		dlt_name: 'DLT_FRELAY',
		description_name:
			' Frame Relay LAPF frames, beginning with a ITU-T Recommendation Q.922 LAPF header starting with the address field, and without an FCS at the end of the frame.',
	},
	108: {
		linktype_name: 'LINKTYPE_LOOP',
		dlt_name: 'DLT_LOOP',
		description_name:
			' OpenBSD loopback encapsulation; the link-layer header is a 4-byte field, in <em>network</em> byte order, containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23 for IPX packets.All of the IPv6 values correspond to IPv6 packets; code reading files should check for all of them.',
	},
	113: {
		linktype_name: 'LINKTYPE_LINUX_SLL',
		dlt_name: 'DLT_LINUX_SLL',
		description_name: ' Linux "cooked" capture encapsulation .',
	},
	114: {
		linktype_name: 'LINKTYPE_LTALK',
		dlt_name: 'DLT_LTALK',
		description_name:
			' Apple LocalTalk; the packet begins with an AppleTalk LocalTalk Link Access Protocol header, as described in chapter 1 of Inside AppleTalk, Second Edition .',
	},
	117: {
		linktype_name: 'LINKTYPE_PFLOG',
		dlt_name: 'DLT_PFLOG',
		description_name:
			' OpenBSD pflog; the link-layer header contains a struct pfloghdr structure, as defined by the host on that the file was saved.(This differs from operating system to operating system and release to release; there is nothing in the file to indicate what the layout of that structure is.) ',
	},
	119: {
		linktype_name: 'LINKTYPE_IEEE802_11_PRISM',
		dlt_name: 'DLT_PRISM_HEADER',
		description_name:
			' Prism monitor mode information followed by an 802.11 header.',
	},
	122: {
		linktype_name: 'LINKTYPE_IP_OVER_FC',
		dlt_name: 'DLT_IP_OVER_FC',
		description_name:
			' RFC 2625 IP-over-Fibre Channel, with the link-layer header being the Network_Header as described in that RFC.',
	},
	123: {
		linktype_name: 'LINKTYPE_SUNATM',
		dlt_name: 'DLT_SUNATM',
		description_name:
			' ATM traffic, encapsulated as per the scheme used by SunATM devices .',
	},
	127: {
		linktype_name: 'LINKTYPE_IEEE802_11_RADIOTAP',
		dlt_name: 'DLT_IEEE802_11_RADIO',
		description_name:
			' Radiotap link-layer information followed by an 802.11 header.',
	},
	129: {
		linktype_name: 'LINKTYPE_ARCNET_LINUX',
		dlt_name: 'DLT_ARCNET_LINUX',
		description_name:
			' ARCNET Data Packets, as described by the ARCNET Trade Association standard RFC 1201 ; for RFC 1051 frames, ATA 878.2 is not used.',
	},
	138: {
		linktype_name: 'LINKTYPE_APPLE_IP_OVER_IEEE1394',
		dlt_name: 'DLT_APPLE_IP_OVER_IEEE1394',
		description_name: ' Apple IP-over-IEEE 1394 cooked header .',
	},
	139: {
		linktype_name: 'LINKTYPE_MTP2_WITH_PHDR',
		dlt_name: 'DLT_MTP2_WITH_PHDR',
		description_name:
			' Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703 , preceded by a pseudo-header.',
	},
	140: {
		linktype_name: 'LINKTYPE_MTP2',
		dlt_name: 'DLT_MTP2',
		description_name:
			' Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703 .',
	},
	141: {
		linktype_name: 'LINKTYPE_MTP3',
		dlt_name: 'DLT_MTP3',
		description_name:
			' Signaling System 7 Message Transfer Part Level 3, as specified by ITU-T Recommendation Q.704 , with no MTP2 header preceding the MTP3 packet.',
	},
	142: {
		linktype_name: 'LINKTYPE_SCCP',
		dlt_name: 'DLT_SCCP',
		description_name:
			' Signaling System 7 Signalling Connection Control Part, as specified by ITU-T Recommendation Q.714 , with no MTP3 or MTP2 headers preceding the SCCP packet.',
	},
	143: {
		linktype_name: 'LINKTYPE_DOCSIS',
		dlt_name: 'DLT_DOCSIS',
		description_name:
			' DOCSIS MAC frames, as described by the DOCSIS 3.1 MAC and Upper Layer Protocols Interface Specification or earlier specifications for MAC frames.',
	},
	144: {
		linktype_name: 'LINKTYPE_LINUX_IRDA',
		dlt_name: 'DLT_LINUX_IRDA',
		description_name:
			' Linux-IrDA packets, with a IrDA Data Specifications , including the IrDA Link Access Protocol specification.',
	},
	147: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	148: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	149: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	150: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	151: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	152: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	153: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	154: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	155: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	156: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	157: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	158: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	159: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	160: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	161: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	162: {
		linktype_name: 'LINKTYPE_USER0–LINKTYPE_USER15',
		dlt_name: 'DLT_USER0–DLT_USER15',
		description_name: ' Reserved for private use; see above.',
	},
	163: {
		linktype_name: 'LINKTYPE_IEEE802_11_AVS',
		dlt_name: 'DLT_IEEE802_11_RADIO_AVS',
		description_name:
			' AVS monitor mode information followed by an 802.11 header.',
	},
	165: {
		linktype_name: 'LINKTYPE_BACNET_MS_TP',
		dlt_name: 'DLT_BACNET_MS_TP',
		description_name:
			' BACnet MS/TP frames, as specified by section 9.3 <b>MS/TP Frame Format</b> of ANSI/ASHRAE Standard 135, BACnet® - A Data Communication Protocol for Building Automation and Control Networks , including the preamble and, if present, the Data CRC.',
	},
	166: {
		linktype_name: 'LINKTYPE_PPP_PPPD',
		dlt_name: 'DLT_PPP_PPPD',
		description_name:
			' PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a direction indication—0x00 for incoming and 0x01 for outgoing.',
	},
	169: {
		linktype_name: 'LINKTYPE_GPRS_LLC',
		dlt_name: 'DLT_GPRS_LLC',
		description_name:
			' General Packet Radio Service Logical Link Control, as defined by 3GPP TS 04.64 .',
	},
	170: {
		linktype_name: 'LINKTYPE_GPF_T',
		dlt_name: 'DLT_GPF_T',
		description_name:
			' Transparent-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303 .',
	},
	171: {
		linktype_name: 'LINKTYPE_GPF_F',
		dlt_name: 'DLT_GPF_F',
		description_name:
			' Frame-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303 .',
	},
	177: {
		linktype_name: 'LINKTYPE_LINUX_LAPD',
		dlt_name: 'DLT_LINUX_LAPD',
		description_name:
			' Link Access Procedures on the D Channel (LAPD) frames, as specified by LINKTYPE_LINUX_LAPD header , followed by the Q.921 frame, starting with the address field.',
	},
	182: {
		linktype_name: 'LINKTYPE_MFR',
		dlt_name: 'DLT_MFR',
		description_name:
			' FRF.12 Interface fragmentation format fragmentation header.',
	},
	187: {
		linktype_name: 'LINKTYPE_BLUETOOTH_HCI_H4',
		dlt_name: 'DLT_BLUETOOTH_HCI_H4',
		description_name:
			' Bluetooth HCI UART transport layer; the frame contains an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent  Bluetooth Core specification , followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.',
	},
	189: {
		linktype_name: 'LINKTYPE_USB_LINUX',
		dlt_name: 'DLT_USB_LINUX',
		description_name:
			" USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree.Only the first 48 bytes of that header are present.All fields in the header are in host byte order.When performing a live capture, the host byte order is the byte order of the machine on that the packets are captured.When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block.",
	},
	192: {
		linktype_name: 'LINKTYPE_PPI',
		dlt_name: 'DLT_PPI',
		description_name:
			' Per-Packet Information information, as specified by the Per-Packet Information Header Specification , followed by a packet with the LINKTYPE_ value specified by the pph_dlt field of that header.',
	},
	195: {
		linktype_name: 'LINKTYPE_IEEE802_15_4_WITHFCS',
		dlt_name: 'DLT_IEEE802_15_4_WITHFCS',
		description_name:
			' IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame.',
	},
	196: {
		linktype_name: 'LINKTYPE_SITA',
		dlt_name: 'DLT_SITA',
		description_name: ' Various link-layer types, with SITA .',
	},
	197: {
		linktype_name: 'LINKTYPE_ERF',
		dlt_name: 'DLT_ERF',
		description_name:
			' Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF records.',
	},
	201: {
		linktype_name: 'LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR',
		dlt_name: 'DLT_BLUETOOTH_HCI_H4_WITH_PHDR',
		description_name:
			' Bluetooth HCI UART transport layer; the frame contains a 4-byte direction field, in network byte order (big-endian), the low-order bit of which is set if the frame was sent from the host to the controller and clear if the frame was received by the host from the controller, followed by an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent  Bluetooth Core specification , followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.',
	},
	202: {
		linktype_name: 'LINKTYPE_AX25_KISS',
		dlt_name: 'DLT_AX25_KISS',
		description_name: ' KISS header containing a type indicator.',
	},
	203: {
		linktype_name: 'LINKTYPE_LAPD',
		dlt_name: 'DLT_LAPD',
		description_name:
			' Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.921 , starting with the address field, with no pseudo-header.',
	},
	204: {
		linktype_name: 'LINKTYPE_PPP_WITH_DIR',
		dlt_name: 'DLT_PPP_WITH_DIR',
		description_name:
			' PPP, as per RFC 1662 , preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host"; if the first 2 bytes are 0xff and 0x03, its PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise its PPP without framing, and the packet begins with the PPP header.The data in the frame is not octet-stuffed or bit-stuffed.',
	},
	205: {
		linktype_name: 'LINKTYPE_C_HDLC_WITH_DIR',
		dlt_name: 'DLT_C_HDLC_WITH_DIR',
		description_name:
			' Cisco PPP with HDLC framing, as per  section 4.3.1 of RFC 1547 , preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host".',
	},
	206: {
		linktype_name: 'LINKTYPE_FRELAY_WITH_DIR',
		dlt_name: 'DLT_FRELAY_WITH_DIR',
		description_name:
			' Frame Relay LAPF frames, beginning with a one-byte pseudo-header with a zero value meaning "received by this host" (DCE-&gt;DTE) and a non-zero value meaning "sent by this host" (DTE-&gt;DCE), followed by an ITU-T Recommendation Q.922 LAPF header starting with the address field, and without an FCS at the end of the frame.',
	},
	207: {
		linktype_name: 'LINKTYPE_LAPB_WITH_DIR',
		dlt_name: 'DLT_LAPB_WITH_DIR',
		description_name:
			' Link Access Procedure, Balanced (LAPB), as specified by ITU-T Recommendation X.25 , preceded with a one-byte pseudo-header with a zero value meaning "received by this host" (DCE-&gt;DTE) and a non-zero value meaning "sent by this host" (DTE-&gt;DCE).',
	},
	209: {
		linktype_name: 'LINKTYPE_IPMB_LINUX',
		dlt_name: 'DLT_IPMB_LINUX',
		description_name: ' a Linux-specific pseudo-header .',
	},
	210: {
		linktype_name: 'LINKTYPE_FLEXRAY',
		dlt_name: 'DLT_FLEXRAY',
		description_name: ' pseudo-header .',
	},
	212: {
		linktype_name: 'LINKTYPE_LIN',
		dlt_name: 'DLT_LIN',
		description_name: ' pseudo-header .',
	},
	215: {
		linktype_name: 'LINKTYPE_IEEE802_15_4_NONASK_PHY',
		dlt_name: 'DLT_IEEE802_15_4_NONASK_PHY',
		description_name:
			' IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame, and with the PHY-level data for the O-QPSK, BPSK, GFSK, MSK, and RCC DSS BPSK PHYs (4 octets of 0 as preamble, one octet of SFD, one octet of frame length + reserved bit) preceding the MAC-layer data (starting with the frame control field).',
	},
	220: {
		linktype_name: 'LINKTYPE_USB_LINUX_MMAPPED',
		dlt_name: 'DLT_USB_LINUX_MMAPPED',
		description_name:
			" USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree.All 64 bytes of the header are present.All fields in the header are in host byte order.When performing a live capture, the host byte order is the byte order of the machine on that the packets are captured.When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block.For isochronous transfers, the ndesc field specifies the number of isochronous descriptors that follow.",
	},
	224: {
		linktype_name: 'LINKTYPE_FC_2',
		dlt_name: 'DLT_FC_2',
		description_name:
			' Fibre Channel FC-2 frames, beginning with a Frame_Header.',
	},
	225: {
		linktype_name: 'LINKTYPE_FC_2_WITH_FRAME_DELIMS',
		dlt_name: 'DLT_FC_2_WITH_FRAME_DELIMS',
		description_name:
			' Fibre Channel FC-2 frames, beginning an encoding of the SOF, followed by a Frame_Header, and ending with an encoding of the SOF.<p> The encodings represent the frame delimiters as 4-byte sequences representing the corresponding ordered sets, with K28.5 represented as 0xBC, and the D symbols as the corresponding byte values; for example, SOFi2, which is K28.5 - D21.5 - D1.2 - D21.2, is represented as 0xBC 0xB5 0x55 0x55.</p>',
	},
	226: {
		linktype_name: 'LINKTYPE_IPNET',
		dlt_name: 'DLT_IPNET',
		description_name:
			' Solaris ipnet pseudo-header , followed by an IPv4 or IPv6 datagram.',
	},
	227: {
		linktype_name: 'LINKTYPE_CAN_SOCKETCAN',
		dlt_name: 'DLT_CAN_SOCKETCAN',
		description_name:
			' CAN (Controller Area Network) frames, with a pseudo-header followed by the frame payload.',
	},
	228: {
		linktype_name: 'LINKTYPE_IPV4',
		dlt_name: 'DLT_IPV4',
		description_name: ' Raw IPv4; the packet begins with an IPv4 header.',
	},
	229: {
		linktype_name: 'LINKTYPE_IPV6',
		dlt_name: 'DLT_IPV6',
		description_name: ' Raw IPv6; the packet begins with an IPv6 header.',
	},
	230: {
		linktype_name: 'LINKTYPE_IEEE802_15_4_NOFCS',
		dlt_name: 'DLT_IEEE802_15_4_NOFCS',
		description_name:
			' IEEE 802.15.4 Low-Rate Wireless Network, without the FCS at the end of the frame.',
	},
	231: {
		linktype_name: 'LINKTYPE_DBUS',
		dlt_name: 'DLT_DBUS',
		description_name:
			' Raw  authentication handshake before the message sequence.',
	},
	235: {
		linktype_name: 'LINKTYPE_DVB_CI',
		dlt_name: 'DLT_DVB_CI',
		description_name:
			' DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification .',
	},
	236: {
		linktype_name: 'LINKTYPE_MUX27010',
		dlt_name: 'DLT_MUX27010',
		description_name:
			' Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but <em>not</em> the same as, 27.010).',
	},
	237: {
		linktype_name: 'LINKTYPE_STANAG_5066_D_PDU',
		dlt_name: 'DLT_STANAG_5066_D_PDU',
		description_name:
			' D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs.The current version of STANAG 5066 is backwards-compatible with  the 1.0.2 version , although newer versions are classified.',
	},
	239: {
		linktype_name: 'LINKTYPE_NFLOG',
		dlt_name: 'DLT_NFLOG',
		description_name: ' Linux netlink NETLINK NFLOG socket log messages.',
	},
	240: {
		linktype_name: 'LINKTYPE_NETANALYZER',
		dlt_name: 'DLT_NETANALYZER',
		description_name:
			' Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices , followed by an Ethernet frame, beginning with the MAC header and ending with the FCS.',
	},
	241: {
		linktype_name: 'LINKTYPE_NETANALYZER_TRANSPARENT',
		dlt_name: 'DLT_NETANALYZER_TRANSPARENT',
		description_name:
			' Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices , followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS.',
	},
	242: {
		linktype_name: 'LINKTYPE_IPOIB',
		dlt_name: 'DLT_IPOIB',
		description_name:
			' IP-over-InfiniBand, as specified by RFC 4391 section 6 .',
	},
	243: {
		linktype_name: 'LINKTYPE_MPEG_2_TS',
		dlt_name: 'DLT_MPEG_2_TS',
		description_name:
			' MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ ITU-T Recommendation H.222.0 (see table 2-2 of section 2.4.3.2 "Transport Stream packet layer").',
	},
	244: {
		linktype_name: 'LINKTYPE_NG40',
		dlt_name: 'DLT_NG40',
		description_name:
			' ITU-T Recommendation Q.2110 for ATM AAL5 traffic, and by NBAP packets for SCTP traffic.',
	},
	245: {
		linktype_name: 'LINKTYPE_NFC_LLCP',
		dlt_name: 'DLT_NFC_LLCP',
		description_name: ' NFCForum-TS-LLCP_1.1 .',
	},
	247: {
		linktype_name: 'LINKTYPE_INFINIBAND',
		dlt_name: 'DLT_INFINIBAND',
		description_name:
			' Raw InfiniBand frames, starting with the Local Routing Header, as specified in Chapter 5 "Data packet format" of InfiniBand™ Architectural Specification Release 1.2.1 Volume 1 - General Specifications .',
	},
	248: {
		linktype_name: 'LINKTYPE_SCTP',
		dlt_name: 'DLT_SCTP',
		description_name:
			' SCTP packets, as defined by RFC 4960 , with no lower-level protocols such as IPv4 or IPv6.',
	},
	249: {
		linktype_name: 'LINKTYPE_USBPCAP',
		dlt_name: 'DLT_USBPCAP',
		description_name: ' USB packets, beginning with a USBPcap header .',
	},
	250: {
		linktype_name: 'LINKTYPE_RTAC_SERIAL',
		dlt_name: 'DLT_RTAC_SERIAL',
		description_name:
			' Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product , followed by a payload for one of a number of industrial control protocols.',
	},
	251: {
		linktype_name: 'LINKTYPE_BLUETOOTH_LE_LL',
		dlt_name: 'DLT_BLUETOOTH_LE_LL',
		description_name:
			' Bluetooth Low Energy air interface Link Layer packets, in the format described in section 2.1 "PACKET FORMAT" of volume 6 of the Bluetooth Specification Version 4.0 (see PDF page 2200), but without the Preamble.',
	},
	253: {
		linktype_name: 'LINKTYPE_NETLINK',
		dlt_name: 'DLT_NETLINK',
		description_name: ' Linux Netlink capture encapsulation .',
	},
	254: {
		linktype_name: 'LINKTYPE_BLUETOOTH_LINUX_MONITOR',
		dlt_name: 'DLT_BLUETOOTH_LINUX_MONITOR',
		description_name:
			' Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack .',
	},
	255: {
		linktype_name: 'LINKTYPE_BLUETOOTH_BREDR_BB',
		dlt_name: 'DLT_BLUETOOTH_BREDR_BB',
		description_name:
			' Bluetooth Basic Rate and Enhanced Data Rate baseband packets .',
	},
	256: {
		linktype_name: 'LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR',
		dlt_name: 'DLT_BLUETOOTH_LE_LL_WITH_PHDR',
		description_name: ' Bluetooth Low Energy link-layer packets .',
	},
	257: {
		linktype_name: 'LINKTYPE_PROFIBUS_DL',
		dlt_name: 'DLT_PROFIBUS_DL',
		description_name:
			' PROFIBUS data link layer packets, as specified by IEC standard 61158-4-3, beginning with the start delimiter, ending with the end delimiter, and including all octets between them.',
	},
	258: {
		linktype_name: 'LINKTYPE_PKTAP',
		dlt_name: 'DLT_PKTAP',
		description_name: ' Apple PKTAP capture encapsulation .',
	},
	259: {
		linktype_name: 'LINKTYPE_EPON',
		dlt_name: 'DLT_EPON',
		description_name:
			' Ethernet-over-passive-optical-network packets, starting with the last 6 octets of the modified preamble as specified by 65.1.3.2 "Transmit" in Clause 65 of Section 5 of IEEE 802.3 , followed immediately by an Ethernet frame.',
	},
	260: {
		linktype_name: 'LINKTYPE_IPMI_HPM_2',
		dlt_name: 'DLT_IPMI_HPM_2',
		description_name:
			' IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in the PICMG HPM.2 specification .The time stamps for packets in this format must match the time stamps in the Trace Data Blocks.',
	},
	261: {
		linktype_name: 'LINKTYPE_ZWAVE_R1_R2',
		dlt_name: 'DLT_ZWAVE_R1_R2',
		description_name:
			' ITU-T Recommendation G.9959 , with some MAC layer fields moved.',
	},
	262: {
		linktype_name: 'LINKTYPE_ZWAVE_R3',
		dlt_name: 'DLT_ZWAVE_R3',
		description_name:
			' ITU-T Recommendation G.9959 , with some MAC layer fields moved.',
	},
	263: {
		linktype_name: 'LINKTYPE_WATTSTOPPER_DLM',
		dlt_name: 'DLT_WATTSTOPPER_DLM',
		description_name:
			' Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures.',
	},
	264: {
		linktype_name: 'LINKTYPE_ISO_14443',
		dlt_name: 'DLT_ISO_14443',
		description_name:
			' Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification .',
	},
	265: {
		linktype_name: 'LINKTYPE_RDS',
		dlt_name: 'DLT_RDS',
		description_name:
			' Radio data system (RDS) groups, as per IEC 62106, encapsulated in this form .',
	},
	266: {
		linktype_name: 'LINKTYPE_USB_DARWIN',
		dlt_name: 'DLT_USB_DARWIN',
		description_name:
			' USB packets, beginning with a Darwin (macOS, etc.) USB header .',
	},
	268: {
		linktype_name: 'LINKTYPE_SDLC',
		dlt_name: 'DLT_SDLC',
		description_name:
			' SDLC packets, as specified by Chapter 1, "DLC Links", section "Synchronous Data Link Control (SDLC)" of Systems Network Architecture Formats, GA27-3136-20 , without the flag fields, zero-bit insertion, or Frame Check Sequence field, containing SNA path information units (PIUs) as the payload.',
	},
	270: {
		linktype_name: 'LINKTYPE_LORATAP',
		dlt_name: 'DLT_LORATAP',
		description_name: ' LoRaWan specification .',
	},
	271: {
		linktype_name: 'LINKTYPE_VSOCK',
		dlt_name: 'DLT_VSOCK',
		description_name:
			' Protocol for communication between host and guest machines in VMware and KVM hypervisors.',
	},
	272: {
		linktype_name: 'LINKTYPE_NORDIC_BLE',
		dlt_name: 'DLT_NORDIC_BLE',
		description_name:
			' Messages to and from a Nordic Semiconductor nRF Sniffer for Bluetooth LE packets, beginning with a pseudo-header .',
	},
	273: {
		linktype_name: 'LINKTYPE_DOCSIS31_XRA31',
		dlt_name: 'DLT_DOCSIS31_XRA31',
		description_name:
			' DOCSIS packets and bursts, preceded by a pseudo-header giving metadata about the packet .',
	},
	274: {
		linktype_name: 'LINKTYPE_ETHERNET_MPACKET',
		dlt_name: 'DLT_ETHERNET_MPACKET',
		description_name:
			' mPackets, as specified by IEEE 802.3br Figure 99-4, starting with the preamble and always ending with a CRC field.',
	},
	275: {
		linktype_name: 'LINKTYPE_DISPLAYPORT_AUX',
		dlt_name: 'DLT_DISPLAYPORT_AUX',
		description_name:
			' DisplayPort AUX channel monitoring data as specified by VESA DisplayPort (DP) Standard preceded by a pseudo-header .',
	},
	276: {
		linktype_name: 'LINKTYPE_LINUX_SLL2',
		dlt_name: 'DLT_LINUX_SLL2',
		description_name: ' Linux "cooked" capture encapsulation v2 .',
	},
	278: {
		linktype_name: 'LINKTYPE_OPENVIZSLA',
		dlt_name: 'DLT_OPENVIZSLA',
		description_name: ' Openvizsla FPGA-based USB sniffer .',
	},
	279: {
		linktype_name: 'LINKTYPE_EBHSCR',
		dlt_name: 'DLT_EBHSCR',
		description_name:
			' Elektrobit High Speed Capture and Replay (EBHSCR) format .',
	},
	280: {
		linktype_name: 'LINKTYPE_VPP_DISPATCH',
		dlt_name: 'DLT_VPP_DISPATCH',
		description_name:
			' Records in traces from the the graph dispatcher trace format .',
	},
	281: {
		linktype_name: 'LINKTYPE_DSA_TAG_BRCM',
		dlt_name: 'DLT_DSA_TAG_BRCM',
		description_name:
			' Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header.',
	},
	282: {
		linktype_name: 'LINKTYPE_DSA_TAG_BRCM_PREPEND',
		dlt_name: 'DLT_DSA_TAG_BRCM_PREPEND',
		description_name:
			' Ethernet frames, with a switch tag inserted before the destination address in the Ethernet header.',
	},
	283: {
		linktype_name: 'LINKTYPE_IEEE802_15_4_TAP',
		dlt_name: 'DLT_IEEE802_15_4_TAP',
		description_name:
			' pseudo-header containing TLVs with metadata preceding the 802.15.4 header.',
	},
	284: {
		linktype_name: 'LINKTYPE_DSA_TAG_DSA',
		dlt_name: 'DLT_DSA_TAG_DSA',
		description_name:
			' Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header.',
	},
	285: {
		linktype_name: 'LINKTYPE_DSA_TAG_EDSA',
		dlt_name: 'DLT_DSA_TAG_EDSA',
		description_name:
			' Ethernet frames, with a programmable Ethernet type switch tag inserted between the source address field and the type/length field in the Ethernet header.',
	},
	286: {
		linktype_name: 'LINKTYPE_ELEE',
		dlt_name: 'DLT_ELEE',
		description_name:
			' Payload of lawful intercept packets using the ELEE protocol .The packet begins with the ELEE header; it does not include any transport-layer or lower-layer headers for protcols used to transport ELEE packets.',
	},
	287: {
		linktype_name: 'LINKTYPE_Z_WAVE_SERIAL',
		dlt_name: 'DLT_Z_WAVE_SERIAL',
		description_name:
			' Serial frames transmitted between a host and a Z-Wave chip over an RS-232 or USB serial connection, as described in section 5 of the Z-Wave Serial API Host Application Programming Guide .',
	},
	288: {
		linktype_name: 'LINKTYPE_USB_2_0',
		dlt_name: 'DLT_USB_2_0',
		description_name:
			' USB 2.0, 1.1, or 1.0 packet, beginning with a PID, as described by Chapter 8 "Protocol Layer" of the the Universal Serial Bus Specification Revision 2.0 .',
	},
	289: {
		linktype_name: 'LINKTYPE_ATSC_ALP',
		dlt_name: 'DLT_ATSC_ALP',
		description_name:
			' ATSC Link-Layer Protocol frames, as described in section 5 of the A/330 Link-Layer Protocol specification, found at the ATSC 3.0 standards page , beginning with a Base Header.',
	},
	290: {
		linktype_name: 'LINKTYPE_ETW',
		dlt_name: 'DLT_ETW',
		description_name:
			' Event Tracing for Windows messages, beginning with a pseudo-header .',
	},
	292: {
		linktype_name: 'LINKTYPE_ZBOSS_NCP',
		dlt_name: 'DLT_ZBOSS_NCP',
		description_name:
			' Serial NCP (Network Co-Processor) protocol for Zigbee stack ZBOSS by DSR.header .',
	},
}
