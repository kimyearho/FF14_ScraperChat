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

				// ��Ʈ��ũ ��Ŷ �ʱ�ȭ
				PacketInstance instance = new PacketInstance();
				txtMsg.appendText("Network Connection ... Ready ... \n");

				// ��Ŷ �ڵ鷯 ����
				PcapHandle handle = instance.packetInit();

				// �ڵ鷯 ���Ῡ��
				if (handle.isOpen()) {

					// ���� ���� �޽���
					txtMsg.appendText("Network Connection Success..!\n\n");

					// ��ư ��Ȱ��ȭ
					btn_start.setDisable(true);

					try {

						// ��Ŷ ������ Ŭ����
						PacketSniffing sniffing = new PacketSniffing();
						
						// ��Ŷ ������
						RawPacketListener listener = new RawPacketListener() {
							@Override
							public void gotPacket(byte[] packet) {
								// ��Ŷ ������
								int packetSize = packet.length;
								
								// ������ ������ ��Ŷ
								if (packetSize == 1158) {
									// ������ ���� �޽���(�Է��� �޽���)
									String sendMsg = sniffing.sendFromServer(packet);
									txtMsg.appendText(sendMsg);
								} else if (packetSize == 1206) {
									// Ŭ���̾�Ʈ�� ������ �޽���
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
