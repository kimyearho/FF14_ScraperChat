package com.nodestory.utils;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

import javafx.application.Platform;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;

public class PacketSniffer {
	
	public Button btn_start;

	public TextArea txtMsg;

	public PacketSniffer(TextArea txtMsg, Button btn_start) {
		this.txtMsg = txtMsg;
		this.btn_start = btn_start;
	}

	public void transp() {
		
		try {
			
			// jNetPcap 초기화
			Pcap pcap = packetInit(btn_start);
			
			// 패킷 이벤트 핸들러
			PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
				
				public void nextPacket(PcapPacket packet, String user) {

					Ip4 ip = new Ip4();
					byte[] dIP = new byte[4], sIP = new byte[4];

					if (packet.hasHeader(ip)) {
						dIP = packet.getHeader(ip).destination();
						sIP = packet.getHeader(ip).source();
					} else {
						return;
					}
					
					// 출발지 IP
					String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
					
					// 도착지 IP
					String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
					
					/**
					 *  <pre>
					 *       << 전제조건 >>
					 *       - 어떠한 경우에서도 같은 룸(파티 or 부대) 에서 상대방이 입력한 메세지 패킷 응답은 반드시 받는다.
					 *       - 내가 전송한 메세지 패킷도 상대방이 프로그램을 쓰고 있다면 같은 룸(파티or부대)에서는 반드시 응답을 전달받는다.
					 *       - 아직 확실하지 않지만 캐릭터 마다 전송하는 서버 IP가 맨 뒷자리가 다른듯 하다.
					 *       - 매지션은 37이고, 라이죠는 39, 부캐는 38이다 정확한 규칙을 알기가 어렵다.
					 *  </pre>
					 */
					
					// 패킷 스니핑 인스턴스
					PacketSniffing sniiffer = new PacketSniffing(txtMsg);

					// 클라 -> 서버
					sniiffer.sendPacketToServer(packet, sourceIP, destinationIP);
					
					// 서버 -> 클라
					sniiffer.receivePacketToClient(packet, sourceIP, destinationIP);

				}

			};
			
			// 실시간으로 패킷을 가져온다.
			pcap.loop(-1, jpacketHandler, "jNetPcap rocks!");
			pcap.close();
			
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
	}
	
	// 패킷 초기화
	private Pcap packetInit(Button btn_start) {
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
		}

		int i = 0;
		String description = "";
		for (PcapIf device : alldevs) {
			description = (device.getDescription() != null) ? device.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}
		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		if (device != null) {
			txtMsg.appendText(description + " 연결 성공! \n\n");
			txtMsg.appendText("# 공지사항\n");
			txtMsg.appendText("=============================================\n");
			txtMsg.appendText("1. 프로그램 사용으로 발생하는 책임은 본인에게 있습니다. \n");
			txtMsg.appendText("2. 버그 및 문의사항은 github에 남겨주세요. \n");
			txtMsg.appendText("https://github.com/kimyearho/FF14_ScraperChat \n");
			txtMsg.appendText("=============================================\n");
			txtMsg.appendText("\t\t\t<듀란달 / Zunk Force> \n\n");
			Platform.runLater(new Runnable() {
				@Override
				public void run() {
					btn_start.setText("Success EtherNet Connection!");
					btn_start.setDisable(true);
				}
			});
		}

		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_BLOCKING;
		int timeout = 1 * 1000; // 10 seconds in millis

		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return pcap;
		}
		
		return pcap;
		
	}

}
