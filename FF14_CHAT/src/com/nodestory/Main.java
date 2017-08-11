package com.nodestory;

import java.io.IOException;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;

public class Main extends Application {

	private Parent rootNode;
	private FXMLLoader fxmlLoader;

	private double xOffset = 0;
	private double yOffset = 0;

	@FXML
	public TextArea txtMsg;
	
	// 메인 프레임 초기화
	public void init() throws IOException {
		fxmlLoader = new FXMLLoader(getClass().getResource("views/MainFrame.fxml"));
		rootNode = fxmlLoader.load();
	}

	@Override
	public void start(Stage primaryStage) {

		try {
			
			// 마우스 클릭 중 일때 ...
			rootNode.setOnMousePressed(new EventHandler<MouseEvent>() {
				@Override
				public void handle(MouseEvent event) {
					xOffset = event.getSceneX();
					yOffset = event.getSceneY();
				}
			});
			
			// 마우스를 드래그 중 일때 ...
			rootNode.setOnMouseDragged(new EventHandler<MouseEvent>() {
				@Override
				public void handle(MouseEvent event) {
					primaryStage.setX(event.getScreenX() - xOffset);
					primaryStage.setY(event.getScreenY() - yOffset);
				}
			});
			
			// 루트 씬
			Scene scene = new Scene(rootNode);
			
			// 루트 스테이지 정보 세팅
			primaryStage.initStyle(StageStyle.DECORATED);
			primaryStage.setTitle("FINAL FANTASY XIV - Scraper Chat v0.1");
			primaryStage.setScene(scene);
			primaryStage.setResizable(false);
			primaryStage.sizeToScene();
			primaryStage.setOpacity(1);
			primaryStage.setAlwaysOnTop(true);
			primaryStage.show();

			// 루트 스테이지 종료 이벤트
			primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
				@Override
				public void handle(WindowEvent event) {
					System.exit(0);
				}
			});

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static void main(String[] args) {
		launch(args);
	}
}
