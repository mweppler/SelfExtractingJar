/*
 * Extractor.java
 * Created on Oct 24, 2009, 8:49 AM
 * Modified on Nov 11, 2010 2:00 PM
 * @author Matthew Weppler
 * copyright 2010 InterDev Inc.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.ProgressMonitor;

public class Extractor extends JFrame {

	private static String MANIFEST = "META-INF/MANIFEST.MF";
	private byte[] salt = {
			(byte) 0x71, (byte) 0x86, (byte) 0x12, (byte) 0x98,
			(byte) 0x61, (byte) 0x77, (byte) 0x61, (byte) 0xEA}; // 8-byte Salt
	private Cipher dcipher;
	private String extractorClass;
	private int iterationCount = 11; // Iteration count
	private File outFile;

	public static void main(String[] args) {
		try {
			Extractor extractor = new Extractor();
			extractor.desEncryptor(extractor.encryptionKeyPrompt());
			String jarFileName = extractor.retrieveJarFileName();
			File destination = extractor.fileDestinationPrompt(jarFileName);
			extractor.selfExtraction(destination, jarFileName); // Extract Jar
			System.exit(NORMAL);
		} catch (Exception e) {
			System.exit(ERROR);
		}
	}

	/**
	 * METHOD: DECRYPT THE FILE
	 * @param encFile
	 * Create a FileInputStream to read the encrypted data & a FileOutputStream for the decrypted data
	 */
	private void decryptTheFile(File encFile) {
		try {
			InputStream in = new FileInputStream(encFile);

			// Set filename for Decrypted file
			File temp = new File(encFile.toString().substring(0, encFile.toString().length() - 4));
			OutputStream out = new FileOutputStream(temp);

			// Bytes read from in will be decrypted
			in = new CipherInputStream(in, dcipher);

			// Read in the decrypted bytes and write the cleartext to out
			byte[] tempByteBuffer = new byte[1024];
			int numRead = 0;
			while ((numRead = in.read(tempByteBuffer)) >= 0) {
				out.write(tempByteBuffer, 0, numRead);
			}
			out.close();
			encFile.delete();
		} catch (IOException ioe) {
			// DO NOTHING WITH THE ERROR
		}
	}
	
	/**
	 * METHOD: DES ENCRYPTER
	 * @param passPhrase
	 */
	private void desEncryptor(String passPhrase) {
		try {
			KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
			SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
			dcipher = Cipher.getInstance(key.getAlgorithm());
			AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
			dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
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
		JDialog dialog = jop.createDialog("Enter the Encryption Key:");
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
	 * METHOD: FILE DESTINATION PROMPT
	 * @param jarFileName
	 * @return file destination
	 * Creates a File Directory Selection Prompt. Returns the selection.
	 */
	private File fileDestinationPrompt(String jarFileName) {
		File jarFile = new File(jarFileName);
		JFileChooser fc = new JFileChooser();
		fc.setCurrentDirectory(new File("."));
		fc.setDialogType(JFileChooser.OPEN_DIALOG);
		fc.setDialogTitle("Select destination directory for extracting " + jarFile.getName());
		fc.setMultiSelectionEnabled(false);
		fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		if (fc.showDialog(Extractor.this, "Select") != JFileChooser.APPROVE_OPTION) {
			return null;  //only when user select valid dir, it can return approve_option
		}
		return fc.getSelectedFile();
	}
	
	/**
	 * METHOD: RETRIEVE JAR FILE NAME
	 * @return Jar File Name
	 * Determines the Jar File Name
	 */
	private String retrieveJarFileName() {
		extractorClass = this.getClass().getName() + ".class";
		//this.getClass().getClassLoader();
		URL urlJar = ClassLoader.getSystemResource(extractorClass);
		String urlStr = urlJar.toString();
		int from = "jar:file:".length();
		int to = urlStr.indexOf("!/");
		return urlStr.substring(from, to);
	}

	/**
	 * METHOD: SELF EXTRACTION
	 * @param outDestination
	 * @param str
	 */
	private void selfExtraction(File outDestination, String str) {
		// TODO Break this method up.
		File outputDir = outDestination;
		SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy hh:mma", Locale.getDefault());
		ProgressMonitor pm = null;
		boolean overwrite = false;

		ZipFile zf = null;
		FileOutputStream out = null;
		InputStream in = null;

		try {
			zf = new ZipFile(str);

			int size = zf.size();
			int extracted = 0;
			pm = new ProgressMonitor(getParent(), "Extracting files...", "starting", 0, size - 4);
			pm.setMillisToDecideToPopup(0);
			pm.setMillisToPopup(0);

			Enumeration entries = zf.entries();

			for (int i = 0; i < size; i++) {
				ZipEntry entry = (ZipEntry) entries.nextElement();
				if (entry.isDirectory()) {
					continue;
				}

				String pathname = entry.getName();
				if (extractorClass.equals(pathname) || MANIFEST.equals(pathname.toUpperCase())) {
					continue;
				}

				pm.setProgress(i);
				pm.setNote(pathname);
				if (pm.isCanceled()) {
					return;
				}

				in = zf.getInputStream(entry);
				outFile = new File(outputDir, pathname);
				Date archiveTime = new Date(entry.getTime());

				if (overwrite == false) {
					if (outFile.exists()) {
						Object[] options = {"Yes", "Yes To All", "No"};
						Date existTime = new Date(outFile.lastModified());
						Long archiveLen = new Long(entry.getSize());
						String msg = "File name conflict: A file with that name already exists!\n" +
							"\nFile name: " + outFile.getName() + "\nExisting file: " + formatter.format(existTime) + 
							",  " + outFile.length() + "Bytes" + "\nFile in archive:" + formatter.format(archiveTime) + 
							",  " + archiveLen + "Bytes" + "\n\nWould you like to overwrite the file?";
						
						int result = JOptionPane.showOptionDialog(Extractor.this,
								msg, "Warning", JOptionPane.DEFAULT_OPTION,
								JOptionPane.WARNING_MESSAGE, null, options, options[0]);

						if (result == 2) { // No
							continue;
						} else if (result == 1) { //YesToAll
							overwrite = true;
						}
					}
				}

				File parent = new File(outFile.getParent());
				if (parent != null && !parent.exists()) {
					parent.mkdirs();
				}

				out = new FileOutputStream(outFile);
				byte[] tempByteBuffer = new byte[1024];
				while (true) {
					int nRead = in.read(tempByteBuffer, 0, tempByteBuffer.length);
					if (nRead <= 0) {
						break;
					}
					out.write(tempByteBuffer, 0, nRead);
				}
				out.close();
				outFile.setLastModified(archiveTime.getTime());
				extracted++;
			}

			pm.close();
			zf.close();
			getToolkit().beep();

			JOptionPane.showMessageDialog(Extractor.this,
					"Extracted " + extracted +
					" file" + ((extracted > 1) ? "s" : "") +
					" from the\n" +
					str + "\narchive into the\n" +
					outputDir.getPath() +
					"\ndirectory.",
					"Zip Self Extractor",
					JOptionPane.INFORMATION_MESSAGE);
			String decryptMe = new String(outFile.getAbsoluteFile().toString());
			File decryptMeFile = new File(decryptMe);
			this.decryptTheFile(decryptMeFile);

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (zf != null) {
				try {
					zf.close();
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
			if (in != null) {
				try {
					in.close();
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
		}
	}
	
}