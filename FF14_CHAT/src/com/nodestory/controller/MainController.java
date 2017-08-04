package com.nodestory.controller;

import com.nodestory.utils.PacketSniffer;

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

				PacketSniffer pac = new PacketSniffer(txtMsg, btn_start);
				pac.transp();

				return null;
			}
		};

		Thread thread = new Thread(task);
		thread.start();
		
	}

}
