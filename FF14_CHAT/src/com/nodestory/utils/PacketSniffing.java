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
	 *     클라이언트에서 서버로 보내는 패킷
	 *     주로 사용자가 입력한 채팅 메세지를 보내는 패킷을 분석한다.
	 * </pre>
	 * 
	 * @param packet
	 *            - 패킷
	 * @param sourceIP-
	 *            출발지 IP
	 * @param destinationIP
	 *            - 도착지 IP
	 */
	public void sendPacketToServer(PcapPacket packet, String sourceIP, String destinationIP) {

		// 패킷 사이즈가 1158이고,
		// 그외 도착지 아이피가 172.217.24 로 시작하는 대역이 아닌것,
		// 출발지 아이피가 124.150 로 시작하는 대역이 아닌것,
		if (packet.size() == 1158) {

			System.out.println("클라-> 서버 - 시작IP -> " + sourceIP);
			System.out.println("클라-> 서버 - 도착IP -> " + destinationIP);

			// 0060: 0a 00 74 6f 20 74 68 65 20 6d 6f 6f 6e 20
			String hexdump = packet.toHexdump(packet.size(), true, false, true);

			// 서버로 전송하는 내가 입력한 메세지
			String chatMsg = fromClientHexToServerMsg(hexdump);

			// 내가 전송하는 문자에 한글이나 숫자 영어(대소문자) 공백이 있는지만
			String reg = "[ㄱ-ㅎ|ㅏ-ㅣ|가-힣|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*";
			if (chatMsg.matches(reg)) {
				// 한글이 있다면,

				// 시작
				int flagIndex = hexdump.indexOf("0080:");

				// 끝
				int flagLastIndex = hexdump.indexOf("0090:");

				String parsePacket = hexdump.substring(flagIndex + 6, flagLastIndex);
				String msg = null;

				// 보내는 패킷은 파티챗 과 부대챗 사이즈가 동일하므로, 구분값을 정해서 화면에 보여주는걸

				// 파싱된 패킷에 "01" 패킷이 있는지 체크
				if (parsePacket.indexOf("01") > -1) {
					// 있다면 파티 챗 리시브
					msg = "[파티]<나> : " + chatMsg + "\n";
				} else {
					// 없다면 부대 챗 리시브
					msg = "[자유부대]<나> : " + chatMsg + "\n";
				}

				// 글로벌서버 한글변환도 됨
				txtMsg.appendText(msg);

			}

		}

	}

	/**
	 * <pre>
	 *     서버에서 클라이언트로 보내는 패킷
	 *     주로 다른 사용자가 입력한 채팅 메세지를 보내는 패킷을 분석한다. (파티, FC)
	 * </pre>
	 * 
	 * @param packet-
	 *            패킷
	 * @param sourceIP
	 *            - 출발지 IP
	 * @param destinationIP
	 *            - 도착지 IP
	 */
	public void receivePacketToClient(PcapPacket packet, String sourceIP, String destinationIP) {

		// ============= 서버에서 보내는 패킷 ============ //
		if (packet.size() == 1206 && !sourceIP.matches(".*216.58.*")) {

			System.out.println("서버-> 클라 - 시작IP -> " + sourceIP);
			System.out.println("서버-> 클라 - 도착IP -> " + destinationIP);

			// 캐릭터명 구함
			String charName = fromServerHexToCharName(packet);

			// 대화내용을 번역한다.
			// 번역 기본설정은 일본어 -> 한국어 이며, 한국어로 입력되도 그대로 한국어로 출력됨.
			String chatMsg = GoogleTransAPI.jpTransMessage(fromSeverHexToClientMsg(packet));

			// 서버에서 전송하는 문자에 한글이나 숫자 영어(대소문자), 지정된 특문이나 공백이 있는지만
			String reg = "[ㄱ-ㅎ|ㅏ-ㅣ|가-힣|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*";
			if (chatMsg.matches(reg)) {

				// 패킷 덤프
				String dump = packet.toHexdump();

				// 시작
				int flagIndex = dump.indexOf("0080:");

				// 끝
				int flagLastIndex = dump.indexOf("0090:");

				String parsePacket = dump.substring(flagIndex + 6, flagLastIndex);
				String msg = null;

				// 받는 패킷은 파티챗 과 부대챗 사이즈가 동일하므로, 구분값을 정해서 화면에 보여주는걸 달리해야한다.
				// 파싱된 패킷에 "01" 패킷이 있는지 체크
				if (parsePacket.indexOf("01") > -1) {
					// 있다면 파티 챗 리시브
					msg = "[파티]<" + charName + "> : " + chatMsg + "\n";
				} else {
					// 없다면 부대 챗 리시브
					msg = "[자유부대]<" + charName + "> : " + chatMsg + "\n";
				}

				txtMsg.appendText(msg);

			}

		}

	}

	/**
	 * 본인이 부대 채팅으로 입력하여 서버로 보냄
	 * 
	 * @param hexdump
	 *            - 패킷덤프
	 * @return 바이트 배열을 UTF-8로 변환한 메시지
	 */
	private String fromClientHexToServerMsg(String hexdump) {

		String message = null;

		try {

			// 시작
			int s_index1 = hexdump.indexOf("0080:");
			int s_index2 = hexdump.indexOf("0090:");
			int s_index3 = hexdump.indexOf("00a0:");
			int s_index4 = hexdump.indexOf("00b0:");
			int s_index5 = hexdump.indexOf("00c0:");
			int s_index6 = hexdump.indexOf("00d0:");
			int s_index7 = hexdump.indexOf("00e0:");

			// 끝
			int e_index = hexdump.indexOf("00f0:");

			// 0080 라인
			String row1 = hexdump.substring(s_index1 + 6, s_index2);

			// 0090 라인
			String row2 = hexdump.substring(s_index2 + 6, s_index3);

			// 00a0 라인
			String row3 = hexdump.substring(s_index3 + 6, s_index4);

			// 00b0 라인
			String row4 = hexdump.substring(s_index4 + 6, s_index5);

			// 00c0 라인
			String row5 = hexdump.substring(s_index5 + 6, s_index6);

			// 00d0 라인
			String row6 = hexdump.substring(s_index6 + 6, s_index7);

			// 00e0 라인
			String row7 = hexdump.substring(s_index7 + 6, e_index);

			// 03 5c 제거해야함
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
	 * 서버에서 클라이언트로 메세지 보냄
	 * 
	 * @param hexdump
	 *            - 패킷덤프
	 * @return 바이트 배열을 UTF-8로 변환한 메시지
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

			// 00b0 라인
			String p1 = msgHex.substring(index1 + 6, index2);
			sb.append(p1);

			// 00c0 라인
			String p2 = msgHex.substring(index2 + 6, index3);
			sb.append(p2);

			// 00d0 라인
			String p3 = msgHex.substring(index3 + 6, index4);
			sb.append(p3);

			// 00e0 라인
			String p4 = msgHex.substring(index4 + 6, index5);
			sb.append(p4);

			// 코드 파싱
			String code = sb.toString();
			code = code.replace("\n", "").trim();
			code = code.replace("00", "").trim();
			code = code.replace(" ", "");

			// hex를 바이트 배열로 변환
			byte[] bytes = hexStringToByteArray(code);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;

	}

	/**
	 * 서버에서 클라이언트로 보낸 패킷 중 캐릭터명을 파싱함
	 * 
	 * @param hexdump
	 *            - 패킷덤프
	 * @return 바이트 배열을 UTF-8로 변환한 메시지
	 */
	public static String fromServerHexToCharName(PcapPacket packet) {

		String message = null;

		try {

			String hexd = packet.toHexdump(packet.size(), true, false, true);

			int a = hexd.indexOf("0090:");

			// 0090 라인
			String p1 = hexd.substring(a + 6, hexd.length());

			int a2 = hexd.indexOf("00a0:");
			int a3 = hexd.indexOf("00b0:");

			// 00a0 라인
			String p1_1 = hexd.substring(a2 + 6, a3);

			int b = p1.indexOf("00");
			String p2 = p1.substring(b + 3, p1.length());

			int c = p2.indexOf("00");
			String charHex = p2.substring(0, c).trim();

			// 0090라인과 00a0라인을 합침
			charHex = charHex + " " + p1_1;
			charHex = charHex.replaceAll("00", "").trim();

			// Hex 데이터에 개행과 각 데이터 사이의 공백을 제거한다.
			String hex = charHex.replace("\n", "").replace(" ", "");

			// hex를 바이트 배열로 변환
			byte[] bytes = hexStringToByteArray(hex);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;

	}

	/**
	 * 서버로 보내는 메시지(사용자가 입력한 메시지)
	 * 
	 * @param packet
	 *            - 패킷 바이트배열
	 * @return - 파싱된 메시지
	 */
	public String sendFromServer(byte[] packet) {

		String message = null;
		String c_Packet = ByteArrays.toHexString(packet, " ").replace(" ", "").replaceAll("00", "");

		try {

			// 패킷을 UTF-8로 변환하여 문자열로 리턴받는다.
			String msg = new String(packet, "UTF-8");

			// 필요없는 부분 파싱
			String parseMsg = msg.substring(msg.lastIndexOf("\\"), msg.length()).replace("\\", "").trim();

			// 패턴1: 한글,영문,숫자,특문이 포함되었는지 체크한다.
			Pattern p = Pattern.compile("(^[ㄱ-ㅎ|ㅏ-ㅣ|가-힣|0-9|a-z|A-Z|\\s|!@#$%^&*?()+-.]*$)");
			Matcher m = p.matcher(parseMsg);

			// 패턴1 검색
			if (m.find()) {
				// 패턴 매칭이 성공 했다면

				// 패턴2: 매칭이 성공한 패턴 문자열에 한글이 반드시 포함되는지 체크
				Pattern p1 = Pattern.compile(".*[ㄱ-ㅎ|ㅏ-ㅣ|가-힣]");
				Matcher m1 = p1.matcher(m.group());
				if (m1.find()) {
					// 한글이 반드시 포함된다면

					// 리턴 문자는 패턴1 문자열을 주입한다.
					// 보내는 메시지가 파티와 부대 패킷이 동일하므로 기준을 정한다.
					if (c_Packet.indexOf("035c") > -1) {
						// FC
						message = "[부대]<나>: " + convertInlineMsg(m.group()) + "\n";
					} else {
						// 파티
						message = "[파티]<나>: " + convertInlineMsg(m.group()) + "\n";
					}

				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return message;
	}

	/**
	 * 클라이언트로 보내는 메시지(다른 사용자가 입력한 메시지)
	 * 
	 * @param packet
	 *            - 패킷 바이트배열
	 * @return - 파싱된 메시지
	 */
	public String resiveFromClient(byte[] packet) {
		System.out.println(ByteArrays.toHexString(packet, " "));
		return null;
	}

	/**
	 * <pre>
	 *     입력한 메시지의 문자열을 일정크기마다 개행을 넣어서 문장을 완성한다.
	 *     문자열의 길이가 기준치가 안된다면 그대로 출력한다.
	 * </pre>
	 * 
	 * @param msg - 입력한 문자열
	 * @return sb - 개행이 들어간 문자열
	 */
	public String convertInlineMsg(String msg) {

		int len = 28;
		int m_size = msg.length();

		int count = 0;

		StringBuffer sb = new StringBuffer();
		StringBuffer sb2 = new StringBuffer();

		if (m_size >= len) {
			for (int i = 0; i < m_size; i++) {
				sb.append(msg.charAt(i));
				// System.out.println("("+len+") (" + sb.length() + ") " + sb.toString());
				if (sb.length() >= len) {
					sb2.append(sb.toString() + "\n");
					sb = new StringBuffer();
					if (count == 0) {
						count += 1;

						len = 35;
					}
				}
			}
		} else {
			sb2.append(msg);
		}

		return sb2.toString();
	}

	/**
	 * hex 코드를 바이트 배열로 변환한다.
	 * 
	 * @param hex
	 *            - 완성된 hex 코드
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
