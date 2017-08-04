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

	// 일본어를 한국어로 번역
	@SuppressWarnings("unchecked")
	public static String jpTransMessage(String text) {

		String msg = "";
		String reg = "[0-9|a-z|A-Z|ㄱ-ㅎ|ㅏ-ㅣ|가-힝|!@#$%^&*()+]*";
		if (text.matches(reg)) {
			// 한글 및 특문 및 영어가 포함되어 있으면 번역하지 않는다.
			msg = text;
		} else {
			
			// 그외는 번역한다.
			// 사실 일어를 별도로 정규식을 빼야하는데 모르겠다.

			// 구글 인공지능 번역 API (텍스트명, 텍스트 언어코드, 변환될 언어코드)
			try {
				
				// 일어 문장을 텍스트로 넘긴다.
				Map<String, Object> tranceMap = googleTransMessage(text, "ja", "ko");

				// API 결과 데이터
				Map<String, Object> tMap = (Map<String, Object>) tranceMap.get("data");

				if (tMap != null) {

					// 파싱
					List<Map<String, Object>> list = (List<Map<String, Object>>) tMap.get("translations");

					for (int i = 0; i < list.size(); i++) {

						tranceMap = (Map<String, Object>) list.get(i);

						// 실제 번역된 메세지
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
