package application;

import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;

public class Controller implements Initializable{
	ObservableList<String> list1 = FXCollections.observableArrayList("NIST P192", "NIST P256", "NIST P384", "NIST P521");
	@FXML
		public ComboBox<String> cb1;
		public TextField txtA;
		public TextField txtB;
		public TextField txtP;
		public Button btn1;
		public Button btn2;
		
		public Button btnE1;
		public Button btnE2;
		public Button btnE3;
		public TextField txtE1;
		public TextField txtE2;
		
		public Button btnD1;
		public Button btnD2;
		public Button btnD3;
		public TextField txtD1;
		public TextField txtD2;
   
	
	public KeyPair kP;

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		// TODO Auto-generated method stub
		cb1.setItems(list1);;
		
	}
	
public void changeCombo(ActionEvent event) {
	String idx = cb1.getValue();
	if (idx == "NIST P192") {
        txtA.setText(EllipticCurve.NIST_P_192.getA().toString());
        txtB.setText(EllipticCurve.NIST_P_192.getB().toString());
        txtP.setText(EllipticCurve.NIST_P_192.getP().toString());
    } else if (idx == "NIST P256") {
        txtA.setText(EllipticCurve.NIST_P_256.getA().toString());
        txtB.setText(EllipticCurve.NIST_P_256.getB().toString());
        txtP.setText(EllipticCurve.NIST_P_256.getP().toString());
    } else if (idx == "NIST P384") {
        txtA.setText(EllipticCurve.NIST_P_384.getA().toString());
        txtB.setText(EllipticCurve.NIST_P_384.getB().toString());
        txtP.setText(EllipticCurve.NIST_P_384.getP().toString());
    } else if (idx == "NIST P521") {
        txtA.setText(EllipticCurve.NIST_P_521.getA().toString());
        txtB.setText(EllipticCurve.NIST_P_521.getB().toString());
        txtP.setText(EllipticCurve.NIST_P_521.getP().toString());
    }
	BigInteger parA = new BigInteger(txtA.getText());
    BigInteger parB = new BigInteger(txtB.getText());
    BigInteger parC = new BigInteger(txtP.getText());
    try {
        kP = ECC.generateKeyPair(new EllipticCurve(parA,parB,parC), new Random(System.currentTimeMillis()));
    }
    catch (Exception e){
        
    }
    
}
//Save private key
public void btnaction1(ActionEvent evt) {                                         
    if (kP != null){
        FileChooser chooser = new FileChooser();     
        File f = chooser.showSaveDialog(null);
        String path = f.getAbsolutePath();
        kP.getPrivateKey().saveToFile(path);
        }
    }

//Save public key
public void btnaction2(ActionEvent evt) {                                         
    if (kP != null){
    	FileChooser chooser = new FileChooser();     
        File f = chooser.showSaveDialog(null);
        String path = f.getAbsolutePath();
        kP.getPublicKey().saveToFile(path);
        }
    }

//ENCRYPTION
//Choose file to Encrypt
public void btnE1Action (ActionEvent evt)
	{
		FileChooser chooser = new FileChooser();
        File f = chooser.showOpenDialog(null);
        txtE1.setText(f.getAbsolutePath());
	}
//Choose the public key
public void btnE2Action (ActionEvent evt)
	{
		FileChooser chooser = new FileChooser();
	    File f = chooser.showOpenDialog(null);
	    txtE2.setText(f.getAbsolutePath());
	}

//Encrypt
public void Encrypt(ActionEvent evt)
	{
		String inputFile = txtE1.getText();
		String publicKeyFile = txtE2.getText();
		try {
            Path path = Paths.get(inputFile);
            
            byte[] plainText = Files.readAllBytes(path);
 
            if (publicKeyFile.length() > 1){
                // Use File                
                PublicKey publicKey = new PublicKey(publicKeyFile);

                byte[] byteFile = ECC.encrypt(plainText,publicKey);

                FileChooser chooser = new FileChooser();     
                File f = chooser.showSaveDialog(null);
                String savePath = f.getAbsolutePath();
                FileOutputStream fos = new FileOutputStream(savePath);
                fos.write(byteFile);
                fos.close();
                File f1 = new File(savePath);               
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
	}


//DECRYPTION
//Choose file to Decrypt
public void btnD1Action (ActionEvent evt)
	{
		FileChooser chooser = new FileChooser();
      File f = chooser.showOpenDialog(null);
      txtD1.setText(f.getAbsolutePath());
	}
//Choose the public key
public void btnD2Action (ActionEvent evt)
	{
		FileChooser chooser = new FileChooser();
	    File f = chooser.showOpenDialog(null);
	    txtD2.setText(f.getAbsolutePath());
	}

//Decrypt
public void Decrypt (ActionEvent evt)
	{
	String inputFile = txtD1.getText();
    String privateKeyFile = txtD2.getText();
    try {
        Path path = Paths.get(inputFile);
        byte[] cipherText = Files.readAllBytes(path);

        if ( privateKeyFile.length() > 1){
            // Use File

            PrivateKey privateKey = new PrivateKey(privateKeyFile);

            
            byte[] byteFile = ECC.decrypt(cipherText, privateKey);
            FileChooser chooser = new FileChooser();     
            File f = chooser.showSaveDialog(null);
            String savePath = f.getAbsolutePath();
            FileOutputStream fos = new FileOutputStream(savePath);
            fos.write(byteFile);
            fos.close();
            File f1 = new File(savePath);   

            }
        

    }
    catch (Exception e){
        e.printStackTrace();
    }
	}

}
