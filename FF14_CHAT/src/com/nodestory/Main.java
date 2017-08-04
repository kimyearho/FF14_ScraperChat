package com.nodestory;

import java.io.File;
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

	static {

		try {
			System.load(new File("lib/jnetpcap.dll").getAbsolutePath());
			System.out.println(new File("lib/jnetpcap.dll").getAbsolutePath());
		} catch (Exception e) {
			System.out.println("Native code library failed to load.\n" + e);
			System.exit(1);
		}

	}

	public void init() throws IOException {
		fxmlLoader = new FXMLLoader(getClass().getResource("views/MainFrame.fxml"));
		rootNode = fxmlLoader.load();
	}

	@Override
	public void start(Stage primaryStage) {

		try {

			rootNode.setOnMousePressed(new EventHandler<MouseEvent>() {
				@Override
				public void handle(MouseEvent event) {
					xOffset = event.getSceneX();
					yOffset = event.getSceneY();
				}
			});
			rootNode.setOnMouseDragged(new EventHandler<MouseEvent>() {
				@Override
				public void handle(MouseEvent event) {
					primaryStage.setX(event.getScreenX() - xOffset);
					primaryStage.setY(event.getScreenY() - yOffset);
				}
			});

			Scene scene = new Scene(rootNode);
			primaryStage.initStyle(StageStyle.DECORATED);
			primaryStage.setTitle("FINAL FANTASY XIV - Scraper Chat v0.1");
			primaryStage.setScene(scene);
			primaryStage.setResizable(false);
			primaryStage.sizeToScene();
			primaryStage.setOpacity(1);
			primaryStage.setAlwaysOnTop(true);
			primaryStage.show();

			// Stage 종료 이벤트
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
