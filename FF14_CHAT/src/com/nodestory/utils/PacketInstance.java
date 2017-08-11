package com.nodestory.utils;

import java.net.InetAddress;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

/**
 * ��Ŷ�� �Ҵ�ޱ� ���� ��Ʈ��ũ �������̽� ����
 * 
 * @date 2017-08-11
 * @author KimYeonHo
 */
public class PacketInstance {
	
	// ����Ʈ ������
	private int SNAPLEN = 65536;
	
	// ������ Ÿ�Ӿƿ�
	private int TIME_OUT = 10;

	public PacketInstance() {
		// TODO: �⺻ ������
	}
	
	/**
	 * ��Ʈ��ũ ��Ŷ �ʱ�ȭ
	 * 
	 * @return PcapHandle
	 */
	public PcapHandle packetInit() {

		PcapHandle handle = null;

		try {
			
			// ���� IP �ּ�
			InetAddress local = InetAddress.getLocalHost();
			String localP = local.getHostAddress();
			
			// �����ϰ��� �ϴ� �������̽� ����
			InetAddress addr = InetAddress.getByName(localP);
			PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
			
			// ��Ŷ��� �ڵ鷯 ����
			PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
			handle = nif.openLive(SNAPLEN, mode, TIME_OUT);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return handle;

	}

}
