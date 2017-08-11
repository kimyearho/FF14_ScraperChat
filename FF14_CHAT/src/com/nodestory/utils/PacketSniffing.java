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
	 *     Å¬¶óÀÌ¾ðÆ®¿¡¼­ ¼­¹ö·Î º¸³»´Â ÆÐÅ¶
	 *     ÁÖ·Î »ç¿ëÀÚ°¡ ÀÔ·ÂÇÑ Ã¤ÆÃ ¸Þ¼¼Áö¸¦ º¸³»´Â ÆÐÅ¶À» ºÐ¼®ÇÑ´Ù.
	 * </pre>
	 * 
	 * @param packet
	 *            - ÆÐÅ¶
	 * @param sourceIP-
	 *            Ãâ¹ßÁö IP
	 * @param destinationIP
	 *            - µµÂøÁö IP
	 */
	public void sendPacketToServer(PcapPacket packet, String sourceIP, String destinationIP) {

		// ÆÐÅ¶ »çÀÌÁî°¡ 1158ÀÌ°í,
		// ±×¿Ü µµÂøÁö ¾ÆÀÌÇÇ°¡ 172.217.24 ·Î ½ÃÀÛÇÏ´Â ´ë¿ªÀÌ ¾Æ´Ñ°Í,
		// Ãâ¹ßÁö ¾ÆÀÌÇÇ°¡ 124.150 ·Î ½ÃÀÛÇÏ´Â ´ë¿ªÀÌ ¾Æ´Ñ°Í,
		if (packet.size() == 1158) {

			System.out.println("Å¬¶ó-> ¼­¹ö - ½ÃÀÛIP -> " + sourceIP);
			System.out.println("Å¬¶ó-> ¼­¹ö - µµÂøIP -> " + destinationIP);

			// 0060: 0a 00 74 6f 20 74 68 65 20 6d 6f 6f 6e 20
			String hexdump = packet.toHexdump(packet.size(), true, false, true);

			// ¼­¹ö·Î Àü¼ÛÇÏ´Â ³»°¡ ÀÔ·ÂÇÑ ¸Þ¼¼Áö
			String chatMsg = fromClientHexToServerMsg(hexdump);

			// ³»°¡ Àü¼ÛÇÏ´Â ¹®ÀÚ¿¡ ÇÑ±ÛÀÌ³ª ¼ýÀÚ ¿µ¾î(´ë¼Ò¹®ÀÚ) °ø¹éÀÌ ÀÖ´ÂÁö¸¸
			String reg = "[¤¡-¤¾|¤¿-¤Ó|°¡-ÆR|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*";
			if (chatMsg.matches(reg)) {
				// ÇÑ±ÛÀÌ ÀÖ´Ù¸é,

				// ½ÃÀÛ
				int flagIndex = hexdump.indexOf("0080:");

				// ³¡
				int flagLastIndex = hexdump.indexOf("0090:");

				String parsePacket = hexdump.substring(flagIndex + 6, flagLastIndex);
				String msg = null;

				// º¸³»´Â ÆÐÅ¶Àº ÆÄÆ¼Ãª °ú ºÎ´ëÃª »çÀÌÁî°¡ µ¿ÀÏÇÏ¹Ç·Î, ±¸ºÐ°ªÀ» Á¤ÇØ¼­ È­¸é¿¡ º¸¿©ÁÖ´Â°É

				// ÆÄ½ÌµÈ ÆÐÅ¶¿¡ "01" ÆÐÅ¶ÀÌ ÀÖ´ÂÁö Ã¼Å©
				if (parsePacket.indexOf("01") > -1) {
					// ÀÖ´Ù¸é ÆÄÆ¼ Ãª ¸®½Ãºê
					msg = "[ÆÄÆ¼]<³ª> : " + chatMsg + "\n";
				} else {
					// ¾ø´Ù¸é ºÎ´ë Ãª ¸®½Ãºê
					msg = "[ÀÚÀ¯ºÎ´ë]<³ª> : " + chatMsg + "\n";
				}

				// ±Û·Î¹ú¼­¹ö ÇÑ±Ûº¯È¯µµ µÊ
				txtMsg.appendText(msg);

			}

		}

	}

	/**
	 * <pre>
	 *     ¼­¹ö¿¡¼­ Å¬¶óÀÌ¾ðÆ®·Î º¸³»´Â ÆÐÅ¶
	 *     ÁÖ·Î ´Ù¸¥ »ç¿ëÀÚ°¡ ÀÔ·ÂÇÑ Ã¤ÆÃ ¸Þ¼¼Áö¸¦ º¸³»´Â ÆÐÅ¶À» ºÐ¼®ÇÑ´Ù. (ÆÄÆ¼, FC)
	 * </pre>
	 * 
	 * @param packet-
	 *            ÆÐÅ¶
	 * @param sourceIP
	 *            - Ãâ¹ßÁö IP
	 * @param destinationIP
	 *            - µµÂøÁö IP
	 */
	public void receivePacketToClient(PcapPacket packet, String sourceIP, String destinationIP) {

		// ============= ¼­¹ö¿¡¼­ º¸³»´Â ÆÐÅ¶ ============ //
		if (packet.size() == 1206 && !sourceIP.matches(".*216.58.*")) {

			System.out.println("¼­¹ö-> Å¬¶ó - ½ÃÀÛIP -> " + sourceIP);
			System.out.println("¼­¹ö-> Å¬¶ó - µµÂøIP -> " + destinationIP);

			// Ä³¸¯ÅÍ¸í ±¸ÇÔ
			String charName = fromServerHexToCharName(packet);

			// ´ëÈ­³»¿ëÀ» ¹ø¿ªÇÑ´Ù.
			// ¹ø¿ª ±âº»¼³Á¤Àº ÀÏº»¾î -> ÇÑ±¹¾î ÀÌ¸ç, ÇÑ±¹¾î·Î ÀÔ·ÂµÇµµ ±×´ë·Î ÇÑ±¹¾î·Î Ãâ·ÂµÊ.
			String chatMsg = GoogleTransAPI.jpTransMessage(fromSeverHexToClientMsg(packet));

			// ¼­¹ö¿¡¼­ Àü¼ÛÇÏ´Â ¹®ÀÚ¿¡ ÇÑ±ÛÀÌ³ª ¼ýÀÚ ¿µ¾î(´ë¼Ò¹®ÀÚ), ÁöÁ¤µÈ Æ¯¹®ÀÌ³ª °ø¹éÀÌ ÀÖ´ÂÁö¸¸
			String reg = "[¤¡-¤¾|¤¿-¤Ó|°¡-ÆR|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*";
			if (chatMsg.matches(reg)) {

				// ÆÐÅ¶ ´ýÇÁ
				String dump = packet.toHexdump();

				// ½ÃÀÛ
				int flagIndex = dump.indexOf("0080:");

				// ³¡
				int flagLastIndex = dump.indexOf("0090:");

				String parsePacket = dump.substring(flagIndex + 6, flagLastIndex);
				String msg = null;

				// ¹Þ´Â ÆÐÅ¶Àº ÆÄÆ¼Ãª °ú ºÎ´ëÃª »çÀÌÁî°¡ µ¿ÀÏÇÏ¹Ç·Î, ±¸ºÐ°ªÀ» Á¤ÇØ¼­ È­¸é¿¡ º¸¿©ÁÖ´Â°É ´Þ¸®ÇØ¾ßÇÑ´Ù.
				// ÆÄ½ÌµÈ ÆÐÅ¶¿¡ "01" ÆÐÅ¶ÀÌ ÀÖ´ÂÁö Ã¼Å©
				if (parsePacket.indexOf("01") > -1) {
					// ÀÖ´Ù¸é ÆÄÆ¼ Ãª ¸®½Ãºê
					msg = "[ÆÄÆ¼]<" + charName + "> : " + chatMsg + "\n";
				} else {
					// ¾ø´Ù¸é ºÎ´ë Ãª ¸®½Ãºê
					msg = "[ÀÚÀ¯ºÎ´ë]<" + charName + "> : " + chatMsg + "\n";
				}

				txtMsg.appendText(msg);

			}

		}

	}

	/**
	 * º»ÀÎÀÌ ºÎ´ë Ã¤ÆÃÀ¸·Î ÀÔ·ÂÇÏ¿© ¼­¹ö·Î º¸³¿
	 * 
	 * @param hexdump
	 *            - ÆÐÅ¶´ýÇÁ
	 * @return ¹ÙÀÌÆ® ¹è¿­À» UTF-8·Î º¯È¯ÇÑ ¸Þ½ÃÁö
	 */
	private String fromClientHexToServerMsg(String hexdump) {

		String message = null;

		try {

			// ½ÃÀÛ
			int s_index1 = hexdump.indexOf("0080:");
			int s_index2 = hexdump.indexOf("0090:");
			int s_index3 = hexdump.indexOf("00a0:");
			int s_index4 = hexdump.indexOf("00b0:");
			int s_index5 = hexdump.indexOf("00c0:");
			int s_index6 = hexdump.indexOf("00d0:");
			int s_index7 = hexdump.indexOf("00e0:");

			// ³¡
			int e_index = hexdump.indexOf("00f0:");

			// 0080 ¶óÀÎ
			String row1 = hexdump.substring(s_index1 + 6, s_index2);

			// 0090 ¶óÀÎ
			String row2 = hexdump.substring(s_index2 + 6, s_index3);

			// 00a0 ¶óÀÎ
			String row3 = hexdump.substring(s_index3 + 6, s_index4);

			// 00b0 ¶óÀÎ
			String row4 = hexdump.substring(s_index4 + 6, s_index5);

			// 00c0 ¶óÀÎ
			String row5 = hexdump.substring(s_index5 + 6, s_index6);

			// 00d0 ¶óÀÎ
			String row6 = hexdump.substring(s_index6 + 6, s_index7);

			// 00e0 ¶óÀÎ
			String row7 = hexdump.substring(s_index7 + 6, e_index);

			// 03 5c Á¦°ÅÇØ¾ßÇÔ
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
	 * ¼­¹ö¿¡¼­ Å¬¶óÀÌ¾ðÆ®·Î ¸Þ¼¼Áö º¸³¿
	 * 
	 * @param hexdump
	 *            - ÆÐÅ¶´ýÇÁ
	 * @return ¹ÙÀÌÆ® ¹è¿­À» UTF-8·Î º¯È¯ÇÑ ¸Þ½ÃÁö
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

			// 00b0 ¶óÀÎ
			String p1 = msgHex.substring(index1 + 6, index2);
			sb.append(p1);

			// 00c0 ¶óÀÎ
			String p2 = msgHex.substring(index2 + 6, index3);
			sb.append(p2);

			// 00d0 ¶óÀÎ
			String p3 = msgHex.substring(index3 + 6, index4);
			sb.append(p3);

			// 00e0 ¶óÀÎ
			String p4 = msgHex.substring(index4 + 6, index5);
			sb.append(p4);

			// ÄÚµå ÆÄ½Ì
			String code = sb.toString();
			code = code.replace("\n", "").trim();
			code = code.replace("00", "").trim();
			code = code.replace(" ", "");

			// hex¸¦ ¹ÙÀÌÆ® ¹è¿­·Î º¯È¯
			byte[] bytes = hexStringToByteArray(code);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;

	}

	/**
	 * ¼­¹ö¿¡¼­ Å¬¶óÀÌ¾ðÆ®·Î º¸³½ ÆÐÅ¶ Áß Ä³¸¯ÅÍ¸íÀ» ÆÄ½ÌÇÔ
	 * 
	 * @param hexdump
	 *            - ÆÐÅ¶´ýÇÁ
	 * @return ¹ÙÀÌÆ® ¹è¿­À» UTF-8·Î º¯È¯ÇÑ ¸Þ½ÃÁö
	 */
	public static String fromServerHexToCharName(PcapPacket packet) {

		String message = null;

		try {

			String hexd = packet.toHexdump(packet.size(), true, false, true);

			int a = hexd.indexOf("0090:");

			// 0090 ¶óÀÎ
			String p1 = hexd.substring(a + 6, hexd.length());

			int a2 = hexd.indexOf("00a0:");
			int a3 = hexd.indexOf("00b0:");

			// 00a0 ¶óÀÎ
			String p1_1 = hexd.substring(a2 + 6, a3);

			int b = p1.indexOf("00");
			String p2 = p1.substring(b + 3, p1.length());

			int c = p2.indexOf("00");
			String charHex = p2.substring(0, c).trim();

			// 0090¶óÀÎ°ú 00a0¶óÀÎÀ» ÇÕÄ§
			charHex = charHex + " " + p1_1;
			charHex = charHex.replaceAll("00", "").trim();

			// Hex µ¥ÀÌÅÍ¿¡ °³Çà°ú °¢ µ¥ÀÌÅÍ »çÀÌÀÇ °ø¹éÀ» Á¦°ÅÇÑ´Ù.
			String hex = charHex.replace("\n", "").replace(" ", "");

			// hex¸¦ ¹ÙÀÌÆ® ¹è¿­·Î º¯È¯
			byte[] bytes = hexStringToByteArray(hex);
			message = new String(bytes, StandardCharsets.UTF_8);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return message;

	}

	/**
	 * ¼­¹ö·Î º¸³»´Â ¸Þ½ÃÁö(»ç¿ëÀÚ°¡ ÀÔ·ÂÇÑ ¸Þ½ÃÁö)
	 * 
	 * @param packet - ÆÐÅ¶ ¹ÙÀÌÆ®¹è¿­
	 * @return - ÆÄ½ÌµÈ ¸Þ½ÃÁö
	 */
	public String sendFromServer(byte[] packet) {

		String message = null;
		String c_Packet = ByteArrays.toHexString(packet, " ").replace(" ", "").replaceAll("00", "");

		try {
			
			// ÆÐÅ¶À» UTF-8·Î º¯È¯ÇÏ¿© ¹®ÀÚ¿­·Î ¸®ÅÏ¹Þ´Â´Ù.
			String msg = new String(packet, "UTF-8");
			
			// ÇÊ¿ä¾ø´Â ºÎºÐ ÆÄ½Ì
			String parseMsg = msg.substring(msg.lastIndexOf("\\"), msg.length()).replace("\\", "").trim();
			
			// ÆÐÅÏ1: ÇÑ±Û,¿µ¹®,¼ýÀÚ,Æ¯¹®ÀÌ Æ÷ÇÔµÇ¾ú´ÂÁö Ã¼Å©ÇÑ´Ù.
			Pattern p = Pattern.compile("(^[¤¡-¤¾|¤¿-¤Ó|°¡-ÆR|0-9|a-z|A-Z|\\s|!@#$%^&*()+-.]*$)");
			Matcher m = p.matcher(parseMsg);
			
			// ÆÐÅÏ1 °Ë»ö
			if (m.find()) {
				// ÆÐÅÏ ¸ÅÄªÀÌ ¼º°ø Çß´Ù¸é
				
				// ÆÐÅÏ2: ¸ÅÄªÀÌ ¼º°øÇÑ ÆÐÅÏ ¹®ÀÚ¿­¿¡ ÇÑ±ÛÀÌ ¹Ýµå½Ã Æ÷ÇÔµÇ´ÂÁö Ã¼Å©
				Pattern p1 = Pattern.compile(".*[¤¡-¤¾|¤¿-¤Ó|°¡-ÆR]");
				Matcher m1 = p1.matcher(m.group());
				if (m1.find()) {
					// ÇÑ±ÛÀÌ ¹Ýµå½Ã Æ÷ÇÔµÈ´Ù¸é
					
					// ¸®ÅÏ ¹®ÀÚ´Â ÆÐÅÏ1 ¹®ÀÚ¿­À» ÁÖÀÔÇÑ´Ù.
					// º¸³»´Â ¸Þ½ÃÁö°¡ ÆÄÆ¼¿Í ºÎ´ë ÆÐÅ¶ÀÌ µ¿ÀÏÇÏ¹Ç·Î ±âÁØÀ» Á¤ÇÑ´Ù.
					if(c_Packet.indexOf("035c") > -1) {
						// FC
						message = "[ºÎ´ë]<Me> : " + m.group() + "\n";
					} else {
						// ÆÄÆ¼
						message = "[ÆÄÆ¼]<Me> : " + m.group() + "\n";
					}
					
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return message;
	}

	/**
	 * hex ÄÚµå¸¦ ¹ÙÀÌÆ® ¹è¿­·Î º¯È¯ÇÑ´Ù.
	 * 
	 * @param hex
	 *            - ¿Ï¼ºµÈ hex ÄÚµå
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
