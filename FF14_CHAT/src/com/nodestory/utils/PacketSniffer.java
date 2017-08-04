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
			
			// jNetPcap �ʱ�ȭ
			Pcap pcap = packetInit(btn_start);
			
			// ��Ŷ �̺�Ʈ �ڵ鷯
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
					
					// ����� IP
					String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
					
					// ������ IP
					String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
					
					/**
					 *  <pre>
					 *       << �������� >>
					 *       - ��� ��쿡���� ���� ��(��Ƽ or �δ�) ���� ������ �Է��� �޼��� ��Ŷ ������ �ݵ�� �޴´�.
					 *       - ���� ������ �޼��� ��Ŷ�� ������ ���α׷��� ���� �ִٸ� ���� ��(��Ƽor�δ�)������ �ݵ�� ������ ���޹޴´�.
					 *       - ���� Ȯ������ ������ ĳ���� ���� �����ϴ� ���� IP�� �� ���ڸ��� �ٸ��� �ϴ�.
					 *       - �������� 37�̰�, �����Ҵ� 39, ��ĳ�� 38�̴� ��Ȯ�� ��Ģ�� �˱Ⱑ ��ƴ�.
					 *  </pre>
					 */
					
					// ��Ŷ ������ �ν��Ͻ�
					PacketSniffing sniiffer = new PacketSniffing(txtMsg);

					// Ŭ�� -> ����
					sniiffer.sendPacketToServer(packet, sourceIP, destinationIP);
					
					// ���� -> Ŭ��
					sniiffer.receivePacketToClient(packet, sourceIP, destinationIP);

				}

			};
			
			// �ǽð����� ��Ŷ�� �����´�.
			pcap.loop(-1, jpacketHandler, "jNetPcap rocks!");
			pcap.close();
			
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
	}
	
	// ��Ŷ �ʱ�ȭ
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
			txtMsg.appendText(description + " ���� ����! \n\n");
			txtMsg.appendText("# ��������\n");
			txtMsg.appendText("=============================================\n");
			txtMsg.appendText("1. ���α׷� ������� �߻��ϴ� å���� ���ο��� �ֽ��ϴ�. \n");
			txtMsg.appendText("2. ���� �� ���ǻ����� github�� �����ּ���. \n");
			txtMsg.appendText("https://github.com/kimyearho/FF14_ScraperChat \n");
			txtMsg.appendText("=============================================\n");
			txtMsg.appendText("\t\t\t<����� / Zunk Force> \n\n");
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
