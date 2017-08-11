package com.nodestory.utils;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;

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
		String connIP = null;
		String reg = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

		try {
			
			// 로컬 IP 주소
			InetAddress local = InetAddress.getLocalHost();
			String localP = local.getHostAddress();
			
			List<String> list = new ArrayList<String>();
			List<String> ip_list = getLocalServerIp();
			for(int i = 0; i < ip_list.size(); i++) {
				if(ip_list.get(i).matches(reg)) {
					System.out.println(ip_list.get(i));
					list.add(ip_list.get(i));
				}
			}
			
			// 머신의 실제 아이피가 1개이상일때.
			if(list.size() > 1) {
				for(int i = 0; i < list.size(); i++) {
					if(!list.get(i).equals(localP)) {
						// 로컬 아이피가 아닌것,
						connIP = list.get(i);
					}
				}
			} else {
				connIP = localP;
			}
			
			System.out.println("실제연결 아이피: " + connIP);
			
			// 연결하고자 하는 인터페이스 정의
			InetAddress addr = InetAddress.getByName(connIP);
			PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
			
			// 패킷통신 핸들러 구현
			PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
			handle = nif.openLive(SNAPLEN, mode, TIME_OUT);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return handle;

	}
	
	/**
	 * 머신에서 사용중인 모든 네트워크의 아이피를 가져온다.
	 * 
	 * @return - List<String> - 모든 네트워크 IP리스트
	 */
	public List<String> getLocalServerIp() {
		
		List<String> list = new ArrayList<String>();
		NetworkInterface iface = null;
		try {
		    for (Enumeration ifaces = NetworkInterface.getNetworkInterfaces(); ifaces.hasMoreElements();) {
		        iface = (NetworkInterface) ifaces.nextElement();
		        InetAddress ia = null;

		        for (Enumeration ips = iface.getInetAddresses(); ips.hasMoreElements();) {
		            ia = (InetAddress) ips.nextElement();
		            String address = ia.getHostAddress();
		            if ("127.0.0.1".compareTo(address) != 0) {
		                list.add(address);
		            }
		        }
		    }
		}
		catch (SocketException e) {
		    e.printStackTrace();
		}
		
		return list;
	}

}
