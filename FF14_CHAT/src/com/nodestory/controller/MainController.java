package com.nodestory.controller;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.RawPacketListener;

import com.nodestory.utils.PacketInstance;
import com.nodestory.utils.PacketSniffing;

import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;

public class MainController {

	@FXML
	public TextArea txtMsg;

	@FXML
	public Button btn_start;

	@FXML
	public void showTrans() {

		Task<Void> task = new Task<Void>() {
			public Void call() throws Exception {

				// 네트워크 패킷 초기화
				PacketInstance instance = new PacketInstance();
				txtMsg.appendText("Network Connection ... Ready ... \n");

				// 패킷 핸들러 구현
				PcapHandle handle = instance.packetInit();

				// 핸들러 연결여부
				if (handle.isOpen()) {

					// 연결 성공 메시지
					txtMsg.appendText("Network Connection Success..!\n\n");

					// 버튼 비활성화
					btn_start.setDisable(true);

					try {

						// 패킷 스니핑 클래스
						PacketSniffing sniffing = new PacketSniffing();
						
						// 패킷 리스너
						RawPacketListener listener = new RawPacketListener() {
							@Override
							public void gotPacket(byte[] packet) {
								// 패킷 사이즈
								int packetSize = packet.length;
								
								// 서버로 보내는 패킷
								if (packetSize == 1158) {
									// 서버로 보낸 메시지(입력한 메시지)
									String sendMsg = sniffing.sendFromServer(packet);
									txtMsg.appendText(sendMsg);
								} else if (packetSize == 1206) {
									// 클라이언트로 보내는 메시지
									String reciveMsg = sniffing.resiveFromClient(packet);
								}

							}
						};
						
						handle.loop(-1, listener);
						handle.close();

					} catch (Exception e) {
						e.printStackTrace();
					}

				}
				return null;
			}
		};

		Thread thread = new Thread(task);
		thread.start();

	}

}
