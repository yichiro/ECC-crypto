package application;
	
import java.io.IOException;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.image.Image;
import javafx.scene.Scene;


public class Main extends Application {
	@Override
	public void start(Stage stage) throws IOException {
		 Parent root = FXMLLoader.load(getClass().getResource("MyScene.fxml"));
		    
	        Scene scene = new Scene(root, 610, 300);
	        stage.setTitle("Elliptic Curve Cryptography - KLTN Dao Viet Bang");
	        stage.getIcons().add(new Image("file:///C:/Users/yichi/eclipse-workspace/ECC/src/application/resources/icon.png"));
	        stage.setScene(scene);
	        stage.show();
	        final boolean resizable = stage.isResizable();
	        stage.setResizable(!resizable);
	}
	
	public static void main(String[] args) {
		launch(args);
	}
}
