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
		String connIP = null;
		String reg = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

		try {
			
			// ���� IP �ּ�
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
			
			// �ӽ��� ���� �����ǰ� 1���̻��϶�.
			if(list.size() > 1) {
				for(int i = 0; i < list.size(); i++) {
					if(!list.get(i).equals(localP)) {
						// ���� �����ǰ� �ƴѰ�,
						connIP = list.get(i);
					}
				}
			} else {
				connIP = localP;
			}
			
			System.out.println("�������� ������: " + connIP);
			
			// �����ϰ��� �ϴ� �������̽� ����
			InetAddress addr = InetAddress.getByName(connIP);
			PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
			
			// ��Ŷ��� �ڵ鷯 ����
			PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
			handle = nif.openLive(SNAPLEN, mode, TIME_OUT);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return handle;

	}
	
	/**
	 * �ӽſ��� ������� ��� ��Ʈ��ũ�� �����Ǹ� �����´�.
	 * 
	 * @return - List<String> - ��� ��Ʈ��ũ IP����Ʈ
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
