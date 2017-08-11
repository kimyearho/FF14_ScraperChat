package com.nodestory.utils;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.packet.PcapPacket;
import org.pcap4j.util.ByteArrays;

import javafx.scene.control.TextArea;

public class PacketSniffing {

	public TextArea txtMsg;

	public PacketSniffing(TextArea txtMsg) {
		this.txtMsg = txtMsg;
	}

	public PacketSniffing() {
	}

	/**
	 * <pre>
	 *     Ŭ���̾�Ʈ���� ������ ������ ��Ŷ
	 *     �ַ� ����ڰ� �Է��� ä�� �޼����� ������ ��Ŷ�� �м��Ѵ�.
	 * </pre>
	 * 
	 * @param packet
	 *            - ��Ŷ
	 * @param sourceIP-
	 *            ����� IP
	 * @param destinationIP
	 *            - ������ IP
	 */
	public void sendPacketToServer(PcapPacket packet, String sourceIP, String destinationIP) {

		// ��Ŷ ����� 1158�̰�,
		// �׿� ������ �����ǰ� 172.217.24 �� �����ϴ� �뿪�� �ƴѰ�,
		// ����� �����ǰ� 124.150 �� �����ϴ� �뿪�� �ƴѰ�,
		if (packet.size() == 1158) {

			System.out.println("Ŭ��-> ���� - ����IP -> " + sourceIP);
			System.out.println("Ŭ��-> ���� - ����IP -> " + destinationIP);

			// 0060: 0a 00 74 6f 20 74 68 65 20 6d 6f 6f 6e 20
			String hexdump = packet.toHexdump(packet.size(), true, false, true);

			// ������ �����ϴ� ���� �Է��� �޼���
			String chatMsg = fromClientHexToServerMsg(hexdump);

			// ���� �����ϴ� ���ڿ� �ѱ��̳� ���� ����(��ҹ���) ������ �ִ�����
			String reg = "[��-��|��-��|��-�R|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*";
			if (chatMsg.matches(reg)) {
				// �ѱ��� �ִٸ�,

				// ����
				int flagIndex = hexdump.indexOf("0080:");

				// ��
				int flagLastIndex = hexdump.indexOf("0090:");

				String parsePacket = hexdump.substring(flagIndex + 6, flagLastIndex);
				String msg = null;

				// ������ ��Ŷ�� ��Ƽê �� �δ�ê ����� �����ϹǷ�, ���а��� ���ؼ� ȭ�鿡 �����ִ°�

				// �Ľ̵� ��Ŷ�� "01" ��Ŷ�� �ִ��� üũ
				if (parsePacket.indexOf("01") > -1) {
					// �ִٸ� ��Ƽ ê ���ú�
					msg = "[��Ƽ]<��> : " + chatMsg + "\n";
				} else {
					// ���ٸ� �δ� ê ���ú�
					msg = "[�����δ�]<��> : " + chatMsg + "\n";
				}

				// �۷ι����� �ѱۺ�ȯ�� ��
				txtMsg.appendText(msg);

			}

		}

	}

	/**
	 * <pre>
	 *     �������� Ŭ���̾�Ʈ�� ������ ��Ŷ
	 *     �ַ� �ٸ� ����ڰ� �Է��� ä�� �޼����� ������ ��Ŷ�� �м��Ѵ�. (��Ƽ, FC)
	 * </pre>
	 * 
	 * @param packet-
	 *            ��Ŷ
	 * @param sourceIP
	 *            - ����� IP
	 * @param destinationIP
	 *            - ������ IP
	 */
	public void receivePacketToClient(PcapPacket packet, String sourceIP, String destinationIP) {

		// ============= �������� ������ ��Ŷ ============ //
		if (packet.size() == 1206 && !sourceIP.matches(".*216.58.*")) {

			System.out.println("����-> Ŭ�� - ����IP -> " + sourceIP);
			System.out.println("����-> Ŭ�� - ����IP -> " + destinationIP);

			// ĳ���͸� ����
			String charName = fromServerHexToCharName(packet);

			// ��ȭ������ �����Ѵ�.
			// ���� �⺻������ �Ϻ��� -> �ѱ��� �̸�, �ѱ���� �Էµǵ� �״�� �ѱ���� ��µ�.
			String chatMsg = GoogleTransAPI.jpTransMessage(fromSeverHexToClientMsg(packet));

			// �������� �����ϴ� ���ڿ� �ѱ��̳� ���� ����(��ҹ���), ������ Ư���̳� ������ �ִ�����
			String reg = "[��-��|��-��|��-�R|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*";
			if (chatMsg.matches(reg)) {

				// ��Ŷ ����
				String dump = packet.toHexdump();

				// ����
				int flagIndex = dump.indexOf("0080:");

				// ��
				int flagLastIndex = dump.indexOf("0090:");

				String parsePacket = dump.substring(flagIndex + 6, flagLastIndex);
				String msg = null;

				// �޴� ��Ŷ�� ��Ƽê �� �δ�ê ����� �����ϹǷ�, ���а��� ���ؼ� ȭ�鿡 �����ִ°� �޸��ؾ��Ѵ�.
				// �Ľ̵� ��Ŷ�� "01" ��Ŷ�� �ִ��� üũ
				if (parsePacket.indexOf("01") > -1) {
					// �ִٸ� ��Ƽ ê ���ú�
					msg = "[��Ƽ]<" + charName + "> : " + chatMsg + "\n";
				} else {
					// ���ٸ� �δ� ê ���ú�
					msg = "[�����δ�]<" + charName + "> : " + chatMsg + "\n";
				}

				txtMsg.appendText(msg);

			}

		}

	}

	/**
	 * ������ �δ� ä������ �Է��Ͽ� ������ ����
	 * 
	 * @param hexdump
	 *            - ��Ŷ����
	 * @return ����Ʈ �迭�� UTF-8�� ��ȯ�� �޽���
	 */
	private String fromClientHexToServerMsg(String hexdump) {

		String message = null;

		try {

			// ����
			int s_index1 = hexdump.indexOf("0080:");
			int s_index2 = hexdump.indexOf("0090:");
			int s_index3 = hexdump.indexOf("00a0:");
			int s_index4 = hexdump.indexOf("00b0:");
			int s_index5 = hexdump.indexOf("00c0:");
			int s_index6 = hexdump.indexOf("00d0:");
			int s_index7 = hexdump.indexOf("00e0:");

			// ��
			int e_index = hexdump.indexOf("00f0:");

			// 0080 ����
			String row1 = hexdump.substring(s_index1 + 6, s_index2);

			// 0090 ����
			String row2 = hexdump.substring(s_index2 + 6, s_index3);

			// 00a0 ����
			String row3 = hexdump.substring(s_index3 + 6, s_index4);

			// 00b0 ����
			String row4 = hexdump.substring(s_index4 + 6, s_index5);

			// 00c0 ����
			String row5 = hexdump.substring(s_index5 + 6, s_index6);

			// 00d0 ����
			String row6 = hexdump.substring(s_index6 + 6, s_index7);

			// 00e0 ����
			String row7 = hexdump.substring(s_index7 + 6, e_index);

			// 03 5c �����ؾ���
			String rowStream = row1.concat(row2).concat(row3).concat(row4).concat(row5).concat(row6).concat(row7)
					.replace("\n", " ").replace("00", "").trim();

			String finalHex = rowStream.replace("03", "").replace("5c", "").replace(" ", "");

			byte[] bytes = hexStringToByteArray(finalHex);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;
	}

	/**
	 * �������� Ŭ���̾�Ʈ�� �޼��� ����
	 * 
	 * @param hexdump
	 *            - ��Ŷ����
	 * @return ����Ʈ �迭�� UTF-8�� ��ȯ�� �޽���
	 */
	public static String fromSeverHexToClientMsg(PcapPacket packet) {

		String message = null;

		try {

			String msgHex = packet.toHexdump(packet.size(), true, false, true);

			int index1 = msgHex.indexOf("00b0:");
			int index2 = msgHex.indexOf("00c0:");
			int index3 = msgHex.indexOf("00d0:");
			int index4 = msgHex.indexOf("00e0:");
			int index5 = msgHex.indexOf("00f0:");

			StringBuffer sb = new StringBuffer();

			// 00b0 ����
			String p1 = msgHex.substring(index1 + 6, index2);
			sb.append(p1);

			// 00c0 ����
			String p2 = msgHex.substring(index2 + 6, index3);
			sb.append(p2);

			// 00d0 ����
			String p3 = msgHex.substring(index3 + 6, index4);
			sb.append(p3);

			// 00e0 ����
			String p4 = msgHex.substring(index4 + 6, index5);
			sb.append(p4);

			// �ڵ� �Ľ�
			String code = sb.toString();
			code = code.replace("\n", "").trim();
			code = code.replace("00", "").trim();
			code = code.replace(" ", "");

			// hex�� ����Ʈ �迭�� ��ȯ
			byte[] bytes = hexStringToByteArray(code);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;

	}

	/**
	 * �������� Ŭ���̾�Ʈ�� ���� ��Ŷ �� ĳ���͸��� �Ľ���
	 * 
	 * @param hexdump
	 *            - ��Ŷ����
	 * @return ����Ʈ �迭�� UTF-8�� ��ȯ�� �޽���
	 */
	public static String fromServerHexToCharName(PcapPacket packet) {

		String message = null;

		try {

			String hexd = packet.toHexdump(packet.size(), true, false, true);

			int a = hexd.indexOf("0090:");

			// 0090 ����
			String p1 = hexd.substring(a + 6, hexd.length());

			int a2 = hexd.indexOf("00a0:");
			int a3 = hexd.indexOf("00b0:");

			// 00a0 ����
			String p1_1 = hexd.substring(a2 + 6, a3);

			int b = p1.indexOf("00");
			String p2 = p1.substring(b + 3, p1.length());

			int c = p2.indexOf("00");
			String charHex = p2.substring(0, c).trim();

			// 0090���ΰ� 00a0������ ��ħ
			charHex = charHex + " " + p1_1;
			charHex = charHex.replaceAll("00", "").trim();

			// Hex �����Ϳ� ����� �� ������ ������ ������ �����Ѵ�.
			String hex = charHex.replace("\n", "").replace(" ", "");

			// hex�� ����Ʈ �迭�� ��ȯ
			byte[] bytes = hexStringToByteArray(hex);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;

	}

	/**
	 * ������ ������ �޽���(����ڰ� �Է��� �޽���)
	 * 
	 * @param packet - ��Ŷ ����Ʈ�迭
	 * @return - �Ľ̵� �޽���
	 */
	public String sendFromServer(byte[] packet) {

		String message = null;
		String c_Packet = ByteArrays.toHexString(packet, " ").replace(" ", "").replaceAll("00", "");

		try {
			
			// ��Ŷ�� UTF-8�� ��ȯ�Ͽ� ���ڿ��� ���Ϲ޴´�.
			String msg = new String(packet, "UTF-8");
			
			// �ʿ���� �κ� �Ľ�
			String parseMsg = msg.substring(msg.lastIndexOf("\\"), msg.length()).replace("\\", "").trim();
			
			// ����1: �ѱ�,����,����,Ư���� ���ԵǾ����� üũ�Ѵ�.
			Pattern p = Pattern.compile("(^[��-��|��-��|��-�R|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*$)");
			Matcher m = p.matcher(parseMsg);
			
			// ����1 �˻�
			if (m.find()) {
				// ���� ��Ī�� ���� �ߴٸ�
				
				// ����2: ��Ī�� ������ ���� ���ڿ��� �ѱ��� �ݵ�� ���ԵǴ��� üũ
				Pattern p1 = Pattern.compile(".*[��-��|��-��|��-�R]");
				Matcher m1 = p1.matcher(m.group());
				if (m1.find()) {
					// �ѱ��� �ݵ�� ���Եȴٸ�
					
					// ���� ���ڴ� ����1 ���ڿ��� �����Ѵ�.
					// ������ �޽����� ��Ƽ�� �δ� ��Ŷ�� �����ϹǷ� ������ ���Ѵ�.
					if(c_Packet.indexOf("035c") > -1) {
						// FC
						message = "[�δ�]<Me> : " + m.group() + "\n";
					} else {
						// ��Ƽ
						message = "[��Ƽ]<Me> : " + m.group() + "\n";
					}
					
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return message;
	}

	/**
	 * hex �ڵ带 ����Ʈ �迭�� ��ȯ�Ѵ�.
	 * 
	 * @param hex
	 *            - �ϼ��� hex �ڵ�
	 * @return byte[]
	 */
	public static byte[] hexStringToByteArray(String hex) {
		int l = hex.length();
		byte[] data = new byte[l / 2];
		for (int i = 0; i < l; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}

}
