package com.nodestory.utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

public class GoogleTransAPI {

	private final static String API_KEY = "AIzaSyAhWtrbUULwQ5gmmYkHWkoWOUf3Fpx7gSk";

	// �Ϻ�� �ѱ���� ����
	@SuppressWarnings("unchecked")
	public static String jpTransMessage(String text) {

		String msg = "";
		String reg = "[0-9|a-z|A-Z|��-��|��-��|��-��|!@#$%^&*()+]*";
		if (text.matches(reg)) {
			// �ѱ� �� Ư�� �� ��� ���ԵǾ� ������ �������� �ʴ´�.
			msg = text;
		} else {
			
			// �׿ܴ� �����Ѵ�.
			// ��� �Ͼ ������ ���Խ��� �����ϴµ� �𸣰ڴ�.

			// ���� �ΰ����� ���� API (�ؽ�Ʈ��, �ؽ�Ʈ ����ڵ�, ��ȯ�� ����ڵ�)
			try {
				
				// �Ͼ� ������ �ؽ�Ʈ�� �ѱ��.
				Map<String, Object> tranceMap = googleTransMessage(text, "ja", "ko");

				// API ��� ������
				Map<String, Object> tMap = (Map<String, Object>) tranceMap.get("data");

				if (tMap != null) {

					// �Ľ�
					List<Map<String, Object>> list = (List<Map<String, Object>>) tMap.get("translations");

					for (int i = 0; i < list.size(); i++) {

						tranceMap = (Map<String, Object>) list.get(i);

						// ���� ������ �޼���
						msg = (String) tranceMap.get("translatedText");
					}
				}

			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return msg;
	}

	public static Map<String, Object> googleTransMessage(String text, String source, String target)
			throws UnsupportedEncodingException {

		StringBuffer urlAddr = new StringBuffer();
		urlAddr.append("https://translation.googleapis.com/language/translate/v2");
		urlAddr.append("?q=" + URLEncoder.encode(text, "UTF-8"));
		urlAddr.append("&source=" + source);
		urlAddr.append("&target=" + target);
		urlAddr.append("&model=nmt");
		urlAddr.append("&key=" + API_KEY);

		StringBuffer sBuffer = new StringBuffer();

		Map<String, Object> returnMap = null;

		try {

			URL url = new URL(urlAddr.toString());
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			if (conn != null) {
				conn.setConnectTimeout(3000);
				conn.setUseCaches(false);
				if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
					InputStreamReader isr = new InputStreamReader(conn.getInputStream(), "UTF-8");
					BufferedReader br = new BufferedReader(isr);
					while (true) {
						String line = br.readLine();
						if (line == null) {
							break;
						}
						sBuffer.append(line);
					}
					br.close();
					conn.disconnect();
				} else if (conn.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
					return returnMap;
				}
			}

			ObjectMapper om = new ObjectMapper();
			returnMap = om.readValue(sBuffer.toString(), new TypeReference<Map<String, Object>>() {
			});

		} catch (Exception e) {
			e.printStackTrace();
		}

		return returnMap;
	}

}
