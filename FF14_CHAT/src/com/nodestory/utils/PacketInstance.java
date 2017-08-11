package com.nodestory.utils;

import java.net.InetAddress;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

/**
 * 패킷을 할당받기 위한 네트워크 인터페이스 정의
 * 
 * @date 2017-08-11
 * @author KimYeonHo
 */
public class PacketInstance {
	
	// 바이트 사이즈
	private int SNAPLEN = 65536;
	
	// 스니핑 타임아웃
	private int TIME_OUT = 10;

	public PacketInstance() {
		// TODO: 기본 생성자
	}
	
	/**
	 * 네트워크 패킷 초기화
	 * 
	 * @return PcapHandle
	 */
	public PcapHandle packetInit() {

		PcapHandle handle = null;

		try {
			
			// 로컬 IP 주소
			InetAddress local = InetAddress.getLocalHost();
			String localP = local.getHostAddress();
			
			// 연결하고자 하는 인터페이스 정의
			InetAddress addr = InetAddress.getByName(localP);
			PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
			
			// 패킷통신 핸들러 구현
			PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
			handle = nif.openLive(SNAPLEN, mode, TIME_OUT);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return handle;

	}

}
