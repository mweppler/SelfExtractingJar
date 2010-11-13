/*
 * Encryptor.java
 * Created on Oct 29 2009 1:07 PM
 * Modified on Nov 11 2010 7:19 PM
 * @author Matthew Weppler
 * copyright 2010 InterDev Inc.
 *
 * **Notes on compiling and running**
 * ----------------------------------
 * Build Eclipse Project & Export to Runnable Jar File.
 * 
 */

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

public class Encryptor extends JFrame {

	private String encryptedFilesName;
	private String extractorClassName = "Extractor.class";
	private byte[] salt = {
			(byte) 0x71, (byte) 0x86, (byte) 0x12, (byte) 0x98,
			(byte) 0x61, (byte) 0x77, (byte) 0x61, (byte) 0xEA}; // 8-byte Salt
	private Cipher ecipher;
	int iterationCount = 11; // Iteration count

	public static void main(String[] args) {
		try {
			Encryptor encryptor = new Encryptor();
			encryptor.desEncryptor(encryptor.encryptionKeyPrompt());
			File fileToEncrypt = encryptor.fileToEncryptPrompt();
			encryptor.encryptTheFile(fileToEncrypt); // Encrypt
			Manifest manifestFile = encryptor.createManifestFile();
			encryptor.buildJarFile(manifestFile); // Create Jar
			System.exit(NORMAL);
		} catch (Exception e) {
			System.exit(ERROR);
		}
	}

	/**
	 * METHOD: BUILD JAR FILE
	 * Create the JAR file. 
	 * Compress the files
	 */
	private void buildJarFile(Manifest manifestFile) {
		try {
			String[] filenames = new String[]{encryptedFilesName, extractorClassName};

			String outFilename = encryptedFilesName.substring(0, encryptedFilesName.length() - 4); // Remove the .tmp extension.
			outFilename = new StringBuilder(outFilename).append(".jar").toString();
			JarOutputStream out = new JarOutputStream(new FileOutputStream(outFilename), manifestFile);
			for (int i = 0; i < filenames.length; i++) {
				if (filenames[i].equals(extractorClassName)) { // Extractor Class
					InputStream in = Encryptor.class.getResourceAsStream("/" + extractorClassName);
					out.putNextEntry(new JarEntry(extractorClassName));
					writeJarEntry(in, out);
				} else { // All other files.
					FileInputStream in = new FileInputStream(filenames[i]);
					out.putNextEntry(new JarEntry(filenames[i]));
					writeJarEntry(in, out);
				}
			}

			// Complete the ZIP file
			out.flush();
			out.close();
			File file = new File(encryptedFilesName);
			file.delete();
		} catch (IOException e) {
		}
	}
	
	/**
	 * METHOD: CREATE MANIFEST FILE
	 * @return manifestFile
	 */
	private Manifest createManifestFile() {
		StringBuilder manifestStringBuilder = new StringBuilder();
		manifestStringBuilder.append("Manifest-Version: 1.0");
		manifestStringBuilder.append("\n");
		manifestStringBuilder.append("Main-Class: Extractor");
		manifestStringBuilder.append("\n");
		ByteArrayInputStream is = null;
		Manifest manifest = null;
		try {
			is = new ByteArrayInputStream(manifestStringBuilder.toString().getBytes("UTF-8"));
			manifest = new Manifest(is);
		} catch (UnsupportedEncodingException uee) {
		} catch (IOException ioe) {
		}
		return manifest;
	}

	/**
	 * METHOD: DES ENCRYPTER
	 * @param passPhrase
	 * DES Encryptor
	 */
	private void desEncryptor(String passPhrase) {
		try {
			KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
			SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
			ecipher = Cipher.getInstance(key.getAlgorithm());
			AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
			ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
		} catch (java.security.InvalidAlgorithmParameterException iape) {
		} catch (java.security.spec.InvalidKeySpecException ikse) {
		} catch (javax.crypto.NoSuchPaddingException nspe) {
		} catch (java.security.NoSuchAlgorithmException nsae) {
		} catch (java.security.InvalidKeyException ike) {
		}
	}

	/**
	 * METHOD: ENCRYPTION KEY PROMPT
	 * @return password
	 * Prompts the user for the set encryption key created by the Encryptor.
	 */
	private String encryptionKeyPrompt() {
		String password;
		final JPasswordField jpf = new JPasswordField();
		jpf.grabFocus();
		JOptionPane jop = new JOptionPane(jpf,
				JOptionPane.QUESTION_MESSAGE,
				JOptionPane.OK_CANCEL_OPTION);
		JDialog dialog = jop.createDialog("Enter an Encryption Key:");
		dialog.setVisible(true);
		Integer result = (Integer) jop.getValue();
		dialog.dispose();
		if (result.intValue() == JOptionPane.OK_OPTION) {
			password = new String(jpf.getPassword());
		} else {
			password = null;
			System.exit(ERROR);
		}
		return password;
	}

	/**
	 * METHOD: ENCRYPT THE FILE
	 * @param fileToEncrypt
	 * Set the encrypted file name. Read in the cleartext bytes and write to out.
	 */
	private void encryptTheFile(File fileToEncrypt) {
		try {
			InputStream in = new FileInputStream(fileToEncrypt);
			encryptedFilesName = new StringBuilder(fileToEncrypt.getName()).append(".tmp").toString();
			File temp = new File(fileToEncrypt.getName() + ".tmp");
			OutputStream out = new FileOutputStream(temp);
			out = new CipherOutputStream(out, ecipher);
			byte[] tempByteBuffer = new byte[1024];
			int numRead = 0;
			while ((numRead = in.read(tempByteBuffer)) >= 0) {
				out.write(tempByteBuffer, 0, numRead);
			}
			out.close();
		} catch (IOException ioe) {
		}
	}

	/**
	 * METHOD: FILE TO ENCRYPT PROMPT
	 * @return fileToEncrypt
	 * Choose file to Encrypt
	 */
	private File fileToEncryptPrompt() { 
		JFileChooser fc = new JFileChooser();
		fc.setCurrentDirectory(new File("."));
		fc.setDialogType(JFileChooser.OPEN_DIALOG);
		fc.setDialogTitle("Select file to encrypt");
		fc.setMultiSelectionEnabled(false);
		fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
		if (fc.showDialog(Encryptor.this, "Select") != JFileChooser.APPROVE_OPTION) {
			return null;  //only when user select valid dir, it can return approve_option
		}
		return fc.getSelectedFile();
	}

	/**
	 * METHOD: WRITE JAR ENTRY
	 * @param in
	 * @param out
	 * @return out
	 */
	private JarOutputStream writeJarEntry(InputStream in, JarOutputStream out) {
		byte[] tempByteBuffer = new byte[1024];
		int len = 0;
		try {
			while ((len = in.read(tempByteBuffer)) >= 0) {
				out.write(tempByteBuffer, 0, len);
			}
			out.flush();
			out.closeEntry();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		return out;
	}
	
}