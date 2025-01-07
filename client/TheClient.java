package client;

import java.util.Date;
import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;





public class TheClient {

	private PassThruCardService servClient = null;
	boolean DISPLAY = true;
	boolean loop = true;


	// PART 1 : STORED FILE
	static final byte CLA					= (byte)0x00;
	static final byte P1					= (byte)0x00;
	static final byte P2					= (byte)0x00;
	static final byte UPDATECARDKEY				= (byte)0x14;
	static final byte UNCIPHERFILEBYCARD			= (byte)0x13;
	static final byte CIPHERFILEBYCARD			= (byte)0x12;
	static final byte READFILEFROMCARD			= (byte)0x10;
	static final byte WRITEFILETOCARD			= (byte)0x09;

	static final int BLOC_SIZE = 127;


	// PART 2 : DES ENCRYPTION AND DECRYPTION

	private final static byte ENCRYPT_FILE_DES           	= (byte)0x20;
	private final static byte DECRYPT_FILE_DES           	= (byte)0x21;

	private static final int CHUNK_SIZE = 120;

	public TheClient() {
		try {
			SmartCard.start();
			System.out.print( "Smartcard inserted?... " ); 

			CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null); 

			SmartCard sm = SmartCard.waitForCard (cr);

			if (sm != null) {
				System.out.println ("got a SmartCard object!\n");
			} else
				System.out.println( "did not get a SmartCard object!\n" );

			this.initNewCard( sm ); 

			SmartCard.shutdown();

		} catch( Exception e ) {
			System.out.println( "TheClient error: " + e.getMessage() );
		}
		java.lang.System.exit(0) ;
	}

	private ResponseAPDU sendAPDU(CommandAPDU cmd) {
		return sendAPDU(cmd, true);
	}

	private ResponseAPDU sendAPDU( CommandAPDU cmd, boolean display ) {
		ResponseAPDU result = null;
		try {
			result = this.servClient.sendCommandAPDU( cmd );
			if(display)
				displayAPDU(cmd, result);
		} catch( Exception e ) {
			System.out.println( "Exception caught in sendAPDU: " + e.getMessage() );
			java.lang.System.exit( -1 );
		}
		return result;
	}


	/************************************************
	 * *********** BEGINNING OF TOOLS ***************
	 * **********************************************/


	private String apdu2string( APDU apdu ) {
		return removeCR( HexString.hexify( apdu.getBytes() ) );
	}


	public void displayAPDU( APDU apdu ) {
		System.out.println( removeCR( HexString.hexify( apdu.getBytes() ) ) + "\n" );
	}


	public void displayAPDU( CommandAPDU termCmd, ResponseAPDU cardResp ) {
		System.out.println( "--> Term: " + removeCR( HexString.hexify( termCmd.getBytes() ) ) );
		System.out.println( "<-- Card: " + removeCR( HexString.hexify( cardResp.getBytes() ) ) );
	}


	private String removeCR( String string ) {
		return string.replace( '\n', ' ' );
	}


	/******************************************
	 * *********** END OF TOOLS ***************
	 * ****************************************/
	

	private boolean selectApplet() {
		boolean cardOk = false;
		try {
			CommandAPDU cmd = new CommandAPDU( new byte[] {
				(byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
				    (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62, 
				    (byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
			} );
			ResponseAPDU resp = this.sendAPDU( cmd );
			if( this.apdu2string( resp ).equals( "90 00" ) )
				cardOk = true;
		} catch(Exception e) {
			System.out.println( "Exception caught in selectApplet: " + e.getMessage() );
			java.lang.System.exit( -1 );
		}
		return cardOk;
	}


	private void initNewCard( SmartCard card ) {
		if( card != null )
			System.out.println( "Smartcard inserted\n" );
		else {
			System.out.println( "Did not get a smartcard" );
			System.exit( -1 );
		}

		System.out.println( "ATR: " + HexString.hexify( card.getCardID().getATR() ) + "\n");


		try {
			this.servClient = (PassThruCardService)card.getCardService( PassThruCardService.class, true );
		} catch( Exception e ) {
			System.out.println( e.getMessage() );
		}

		System.out.println("Applet selecting...");
		if( !this.selectApplet() ) {
			System.out.println( "Wrong card, no applet to select!\n" );
			System.exit( 1 );
			return;
		} else 
			System.out.println( "Applet selected" );

		mainLoop();
	}

	/**
	 * Method to create an APDU command.
	 * @param data The data to send to the card.
	 * @param cla The class
	 * @param ins The instruction ID.
	 * @param p1 The parameter 1.
	 * @param p2 The parameter 2.
	 * @return The APDU command in bytes.
	 */
	public static byte[] createAPDUCommandByte(byte[] data, byte cla, byte ins, byte p1, byte p2) {
		int dataLength = data.length;
		byte[] apdu = new byte[5 + dataLength];

		apdu[0] = cla;
		apdu[1] = ins;
		apdu[2] = p1;
		apdu[3] = p2;
		apdu[4] = (byte) dataLength;
		System.arraycopy(data, 0, apdu, 5, dataLength);

		return apdu;
	}

	public static byte[] createAPDUCommand(String strData, byte cla, byte ins, byte p1, byte p2) {
		byte[] dataBytes = strData.getBytes();
		return createAPDUCommandByte(dataBytes, cla, ins, p1, p2);
	}

	/**
	 * Method to create an APDU command without data
	 */
	public static byte[] createAPDUCommandNoData(byte cla, byte ins, byte p1, byte p2) {
		byte [] apdu = new byte[5];

		apdu[0] = cla;
		apdu[1] = ins;
		apdu[2] = p1;
		apdu[3] = p2;
		apdu[4] = 0x00;

		return apdu;
	}

	/**
	 * Method to convert a byte array to a string in ASCII
	 * @param bytes The byte array
	 * @return The string in ASCII.
	 */

	public static String convertByteToASCII(byte[] bytes) {
		if(bytes == null) {
			return "";
		}
		StringBuilder result = new StringBuilder();

		long len =  bytes.length;
		for (int i = 0; i < len - 2; i++) { // I do -2 because the last 2 bytes are the status SW1 SW2.
			if (bytes[i] >= 32 && bytes[i]  <= 126) {
				result.append((char) bytes[i] );
			} else {
				result.append(".");
			}
		}
		return result.toString();
	}

	/**
	 * Method to cipher or decipher a file
	 * https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
	 * @param typeINS cipher or decipher instruction
	 * @param challenge the
	 * @return
	 */
	byte[] cipherGeneric(byte typeINS, byte[] challenge) {

		byte[] apdu = createAPDUCommandByte(challenge, CLA, typeINS, P1, P2);
		CommandAPDU cmd = new CommandAPDU(apdu);


		ResponseAPDU resp = this.sendAPDU(cmd);
		byte[] data = resp.getBytes();


		short sw1 = (short) (data[data.length - 2] & 0xFF);
		short sw2 = (short) (data[data.length - 1] & 0xFF);


		byte[] encryptedData = new byte[data.length - 2];
		System.arraycopy(data, 0, encryptedData, 0, data.length - 2);

		// Here if the card answer me with a 0x61XX (0x61 say that the card encrypted some data for me and XX is the number of bytes)
		while (sw1 == 0x61) {
			// C0 for my GET RESPONSE
			// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
			byte[] getDataAPDU = {(byte)0x00, (byte)0xC0, (byte)0x00, (byte)0x00, (byte)sw2};
			CommandAPDU getResponse = new CommandAPDU(getDataAPDU);
			resp = this.sendAPDU(getResponse);


			byte[] additionalData = resp.getBytes();
			short newSw1 = (short) (additionalData[additionalData.length - 2] & 0xFF);
			short newSw2 = (short) (additionalData[additionalData.length - 1] & 0xFF);


			byte[] newEncryptedPart = new byte[additionalData.length - 2];
			System.arraycopy(additionalData, 0, newEncryptedPart, 0, additionalData.length - 2);

			// I merge two arrays with the new data that have been encrypted or decrypted
			byte[] temp = new byte[encryptedData.length + newEncryptedPart.length];
			System.arraycopy(encryptedData, 0, temp, 0, encryptedData.length);
			System.arraycopy(newEncryptedPart, 0, temp, encryptedData.length, newEncryptedPart.length);


			encryptedData = temp;


			sw1 = newSw1;
			sw2 = newSw2;
		}


		if (sw1 != 0x90 || sw2 != 0x00) {
			System.out.println("[X] Error during DES operation. SW=" + Integer.toHexString(sw1) + " " + Integer.toHexString(sw2));
			return null;
		}


		System.out.println("Encrypted block size: " + encryptedData.length);

		return encryptedData;
	}

	/**
	 * Add padding to the last block of the file (or add one if it is a perfect multiple).
	 * I use PKCS#7 padding in my case
	 * @param data The data to pad
	 * @param blockSize The block size
	 * @return The padded data
	 */
	byte[] addPadding(byte[] data, int blockSize) {
		// Here I calculate the number of bytes that I have to add to the last block
		int paddingSize = blockSize - (data.length % blockSize);

		/**
		if (paddingSize == 0) { // Perfect multiple
			paddingSize = blockSize;
		}
		*/

		byte[] paddedData = new byte[data.length + paddingSize];
		System.arraycopy(data, 0, paddedData, 0, data.length);

		for (int i = data.length; i < paddedData.length; i++) {
			paddedData[i] = (byte) paddingSize;
		}
		return paddedData;
	}

	/**
	 * Remove padding from the last block of the file
	 * @param data The data to depad
	 * @return The unpadded data
	 */
	private byte[] removePadding(byte[] data) {
		if (data.length == 0) {
			return null;
		}

		// Here I get the padding size
		int padSize = data[data.length - 1] & 0xFF;

		// I check if the padding is valid (between 1 and 8 bytes)
		if (padSize < 1 || padSize > 8 || padSize > data.length) {
			return null;
		}

		for (int i = 0; i < padSize; i++) {
			if (data[data.length - 1 - i] != (byte) padSize) {
				return null;
			}
		}


		// I create my data without the padding
		int newLength = data.length - padSize;
		byte[] unpaddedData = new byte[newLength];
		System.arraycopy(data, 0, unpaddedData, 0, newLength);

		return unpaddedData;
	}

	/**
	 * Method to update the DES key of the card
	 */
	void updateCardKey() {
		System.out.println("[!] Warning: Changing the encryption key will make previously encrypted files unreadable");
		System.out.println("[+] - Enter the new DES key (8 bytes): ");
		String key = readKeyboard();

		if(key.length() != 8) {
			System.out.println("[X] - Error: The key must be 8 bytes long, please retry...");
			return;
		}

		byte[] apdu = createAPDUCommand(key, CLA, UPDATECARDKEY, P1, P2);

		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd);

		byte[] respBytes = resp.getBytes();

		int sw1 = (short) (respBytes[respBytes.length - 2] & 0xFF);
		int sw2 = (short) (respBytes[respBytes.length - 1] & 0xFF);

		if(sw1 == 0x90 && sw2 == 0x00) { // Key changed
			System.out.println("[+] - Key updated successfully");
		} else {
			System.out.println("[X] - Error: Key update failed, please retry...");
		}


	}

	/**
	 * Method to decipher a file with DES.
	 */
	void uncipherFileByCard() {
		System.out.println("[+] - Enter the name of the file that you want to decrypt: ");
		String filename = readKeyboard();
		System.out.println("[+] - Enter the output file name (decrypted): ");
		String outputFilename = readKeyboard();

		File file = new File(filename);

		if (!file.exists()) {
			System.out.println("[X] Error: File does not exist, please retry...");
			return;
		}

		FileInputStream fileInStream = null;
		FileOutputStream fileOutStream = null;

		try {
			fileInStream = new FileInputStream(file);
			fileOutStream = new FileOutputStream(outputFilename);

			byte[] bufferIn = new byte[CHUNK_SIZE];
			int contentLen;

			while ((contentLen = fileInStream.read(bufferIn)) != -1) {
				byte[] dataToSend = new byte[contentLen];
				System.arraycopy(bufferIn, 0, dataToSend, 0, contentLen);

				System.out.println("Size of data to decrypt: " + dataToSend.length);

				// First I need to uncipher the data.
				byte[] bufferOut = cipherGeneric(DECRYPT_FILE_DES, dataToSend);

				if (bufferOut == null) {
					System.out.println("[X] Error: Cannot decrypt the file");
					return;
				}

				// This is the last block so I remove padding
				if (fileInStream.available() == 0) {

					byte[] unpaddedData = removePadding(bufferOut);
					if (unpaddedData == null) {
						System.out.println("[X] Error: Cannot remove padding");
						return;
					}

					System.out.println("Decrypted (unpadded) block size: " + unpaddedData.length);
					System.out.println("Decrypted (unpadded) data: " + HexString.hexify(unpaddedData));
					fileOutStream.write(unpaddedData);
				} else { // I don't depad here because not the last block
					System.out.println("Decrypted block size: " + bufferOut.length);
					System.out.println("Decrypted data: " + HexString.hexify(bufferOut));
					fileOutStream.write(bufferOut);
				}
			}

			System.out.println("[+] Decryption done. Output file: " + outputFilename);
		} catch (IOException e) {
			System.out.println("[X] IO Error: " + e.getMessage());
		} finally {
			try {
				if (fileInStream != null) fileInStream.close();
				if (fileOutStream != null) fileOutStream.close();
			} catch (IOException e) {
				System.out.println("[X] Error: closing streams: " + e.getMessage());
			}
		}
	}





	/**
	 * Method to cipher a file with DES.
	 */
	void cipherFileByCard() {
		System.out.println("[+] - Enter the name of the file that you want to encrypt: ");
		String filename = readKeyboard();
		System.out.println("[+] - Enter the output file name (encrypted one): ");
		String outputFilename = readKeyboard();

		File file = new File(filename);

		if (!file.exists()) {
			System.out.println("[X] Error: File does not exist, please retry...");
			return;
		}

		FileInputStream fileInStream = null;
		FileOutputStream fileOutStream = null;

		try {
			fileInStream = new FileInputStream(file);
			fileOutStream = new FileOutputStream(outputFilename);

			byte[] bufferIn = new byte[CHUNK_SIZE];
			int contentLen;

			// I read chunk by chunk my file
			while ((contentLen = fileInStream.read(bufferIn)) != -1) {

				byte[] dataToSend = new byte[contentLen];
				System.arraycopy(bufferIn, 0, dataToSend, 0, contentLen);

				System.out.println("Size of data to encrypt: " + dataToSend.length);

				byte[] bufferOut;

				// That my last bloc so I have to add padding
				if (fileInStream.available() == 0) {

					byte[] paddedData = addPadding(dataToSend, 8);
					bufferOut = cipherGeneric(ENCRYPT_FILE_DES, paddedData);

					if (bufferOut != null && bufferOut.length > 0) {
						System.out.println("Encrypted block size (padded): " + bufferOut.length);
						System.out.println("Encrypted data (padded): " + HexString.hexify(bufferOut));

						fileOutStream.write(bufferOut);
					} else {
						System.out.println("[X] Block encryption failed for the last block");
						return;
					}

					// I don't do anything now because I treated the last block
					break;
				} else {
					// Cipher but with no padding (because I am not at the last block)
					byte[] encryptedData = cipherGeneric(ENCRYPT_FILE_DES, dataToSend);

					if (encryptedData != null && encryptedData.length > 0) {
						System.out.println("Encrypted block size: " + encryptedData.length);
						System.out.println("Encrypted data: " + HexString.hexify(encryptedData));

						fileOutStream.write(encryptedData);
					} else {
						System.out.println("[X] Block encryption failed");
						return;
					}
				}
			}

			System.out.println("[+] Encryption done | Output file: " + outputFilename);
		} catch (IOException e) {
			System.out.println("[X] IO Error: " + e.getMessage());
		} finally {
			try {
				if (fileInStream != null) fileInStream.close();
				if (fileOutStream != null) fileOutStream.close();
			} catch (IOException e) {
				System.out.println("[X] Error: closing streams: " + e.getMessage());
			}
		}
	}
	/**
	 * Function to list files on the card
	 *
	 * P1 = 0x01 : Get the file list as : [index][filenameLength][filename][fileSize]
	 */
	void listFiles() {

		byte[] apdu = createAPDUCommand("", CLA, READFILEFROMCARD, (byte)0x01, (byte)0x00);
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);


		byte[] respBytes = resp.getBytes();
		short length = (short) respBytes.length;

		// I'm checking the status
		int sw1 = (short) (respBytes[length - 2] & 0xFF);
		int sw2 = (short) (respBytes[length - 1] & 0xFF);

		if(sw1 == 0x90 && sw2 == 0x00) {

			byte[] data = new byte[length - 2];
			System.arraycopy(respBytes, 0, data, 0, length - 2);


			if(data.length == 0) {
				System.out.println("[+] - No file on the card");
				return;
			}
			parseFileList(data); // To parse the byte array that I just received in a pretty way
		} else {
			System.out.println("[X] - Error: Can't get the file list");
		}
	}

	/**
	 * Method to parse the file list in a pretty way
	 * @param data The byte array that contain my file list that I just requested with the function listFiles
	 */
	void parseFileList(byte[] data) {
		int offset = 0;
		System.out.println("[+] - Files on the card:");

		while (offset < data.length) {

			// I get the index
			int index = data[offset] & 0xFF;
			offset++;

			int lengthFileName = data[offset] & 0xFF;
			offset++;

			System.out.print("[" + index + "] - ");

			// I read the file name.
			byte[] fileNameBytes = new byte[lengthFileName];
			System.arraycopy(data, offset, fileNameBytes, 0, lengthFileName);
			String fileName = new String(fileNameBytes);
			System.out.print(fileName);

			offset += lengthFileName;

			// I read the file size.
			int highByte = data[offset] & 0xFF;
			int lowByte = data[offset + 1] & 0xFF;

			int fileSize = (highByte << 8) | lowByte;

			offset += 2;
			System.out.println(" " + fileSize + " bytes\n");
		}
	}

	/**
	 * Method to check if the card is out of memory (not enough space)
	 */
	private boolean isMemoryError(ResponseAPDU resp) {
		byte[] respBytes = resp.getBytes();
		int sw1 = (short) (respBytes[respBytes.length - 2] & 0xFF);
		int sw2 = (short) (respBytes[respBytes.length - 1] & 0xFF);

		if (sw1 == 0x6A && sw2 == 0x84) {
			System.out.println("[X] - Error: Not enough memory on the card ! Operation stopped.");
			return true;
		}
		return false;
	}

	/**
	 * Function write a file to the card.
	 * The file is sent in 3 steps:
	 * 1. (0x01) First I send the metadata (filename length and filename in the APDU it initialize also two bit at 0 for the number of blocks and the last block size)
	 * 2. (0x02) I send blocks of 127 bytes from the file
	 * 3. (0x03) I send the last block of the file
	 * */
	void writeFileToCard()  {
		CommandAPDU cmd;
		ResponseAPDU resp;

		System.out.print("[+] - Please give the file path : ");
		String filePath = readKeyboard();

		File file = new File(filePath);
		if(!file.exists()) {
			System.out.println("[X] - Error : File didn't found, please check the path");
			return;
		}

		byte[] fileContent;
		FileInputStream inputStream = null;

		try {
			inputStream = new FileInputStream(file);
			fileContent = new byte[(int) file.length()];

			// I refuse if the file is 0 bytes (because there is no point to stock/write an empty file because there is no information useful)
			if(fileContent.length == 0) {
				System.out.println("[X] - Error: Cannot accept a file empty");
				return;
			}
			inputStream.read(fileContent);
		} catch (IOException e) {
			System.out.println("[X] - Error: Cannot read the file.");
			return;
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					System.out.println("[X] - Error: Cannot close the file input stream.");
				}
			}
		}

		String fileName = file.getName();
		byte[] fileNameBytes = fileName.getBytes();

		// Here I do 254 because I'm going to send in my first APDU for the metadata also the length of the filename
		// That is one byte so I can't have a filename longer than 254 bytes
		if(fileNameBytes.length > 254) {
			System.out.println("[X] - Error: File name too long");
			return;
		}

		// I send the metadata in the first APDU (0x01 P1)
		byte[] metaData = new byte[1 + fileNameBytes.length];
		metaData[0] = (byte) fileNameBytes.length;
		System.arraycopy(fileNameBytes, 0, metaData, 1, fileNameBytes.length);

		byte[] apdu = createAPDUCommandByte(metaData, CLA, WRITEFILETOCARD, (byte)0x01, (byte)0x00);
		cmd = new CommandAPDU(apdu);
		resp = this.sendAPDU(cmd, DISPLAY);

		if (isMemoryError(resp)) return;

		// I read then I send blocks of 127 bytes (0x02 P1)
		// I allocate for that chunk of 127 bytes and put the data in it
		int offset = 0;
		int totalLength = fileContent.length;
		int blockId = 0;
		while((totalLength - offset) > BLOC_SIZE) { // I do that until I have less than 127 bytes to send (for the last block))
			byte[] chunk = new byte[BLOC_SIZE];
			System.arraycopy(fileContent, offset, chunk, 0, BLOC_SIZE);

			apdu = createAPDUCommandByte(chunk, CLA, WRITEFILETOCARD, (byte)0x02, (byte)blockId);
			cmd = new CommandAPDU(apdu);
			resp = this.sendAPDU(cmd, DISPLAY);

			if (isMemoryError(resp)) return;

			offset += BLOC_SIZE; // I increment the offset to read and write the next block of my file
			blockId++;
		}

		// I send the last block of the file (0x03 P1) so less than 127 bytes
		int remaining = totalLength - offset;
		if(remaining > 0) {

			byte[] lastBlock = new byte[remaining];
			System.arraycopy(fileContent, offset, lastBlock, 0, remaining);

			apdu = createAPDUCommandByte(lastBlock, CLA, WRITEFILETOCARD, (byte)0x03, (byte)0x00);
			cmd = new CommandAPDU(apdu);
			resp = this.sendAPDU(cmd, DISPLAY);

			if (isMemoryError(resp)) return;

		}

		System.out.println("[+] - File written to card successfully.");
	}

	/**
	 * Function to read a file by an index
	 * P1 = 0x04 : To get the metadata of the specified file (nbBlocs and lastBlockSize)
	 * P1 = 0x03 : To read the file by blocs | P2 = blocId to know which bloc to read
	 */
	void readFileByIndex() {
		System.out.print("[+] - Please give the file index : ");
		String indexStr = readKeyboard();
		int index = Integer.parseInt(indexStr);


		// I ask metadata of the file (index) to know how many blocs I have to read that I like I'm asking an anuary.
		byte[] apdu = createAPDUCommandNoData(CLA, READFILEFROMCARD, (byte)0x04, (byte)index);
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = sendAPDU(cmd, DISPLAY);

		byte[] respBytes = resp.getBytes();
		int lengthWithSW = respBytes.length;
		int respLength = lengthWithSW - 2;

		int sw1 = respBytes[lengthWithSW - 2] & 0xFF;
		int sw2 = respBytes[lengthWithSW - 1] & 0xFF;


		// I get the metadata of the file
		if (sw1 == 0x90 && sw2 == 0x00 && respLength > 4) {
			int fileNameLength = respLength - 4;
			String fileName = new String(respBytes, 0, fileNameLength);

			short nbBlocks = (short) (((respBytes[fileNameLength] & 0xFF) << 8) | (respBytes[fileNameLength + 1] & 0xFF));
			short lastBlockSize = (short) (((respBytes[fileNameLength + 2] & 0xFF) << 8) | (respBytes[fileNameLength + 3] & 0xFF));

			System.out.println("[+] File found by index " + index + ": name=" + fileName + ", nbBlocks=" + nbBlocks + ", lastBlockSize=" + lastBlockSize);

			ByteArrayOutputStream fileContent = new ByteArrayOutputStream();

			// I read block by block
			for (short blockId = 0; blockId < nbBlocks; blockId++) {
				apdu = createAPDUCommandNoData(CLA, READFILEFROMCARD, (byte) 0x03, (byte)blockId);
				cmd = new CommandAPDU(apdu);
				resp = sendAPDU(cmd, DISPLAY);

				respBytes = resp.getBytes();
				lengthWithSW = respBytes.length;
				respLength = lengthWithSW - 2;
				sw1 = respBytes[lengthWithSW - 2] & 0xFF;
				sw2 = respBytes[lengthWithSW - 1] & 0xFF;

				if (sw1 == 0x90 && sw2 == 0x00 && respLength == BLOC_SIZE) {
					fileContent.write(respBytes, 0, respLength);
				} else {
					System.out.println("[X] Error reading block " + blockId);
					return;
				}
			}

			// I read the last block
			if (lastBlockSize > 0) {
				apdu = createAPDUCommandNoData(CLA, READFILEFROMCARD, (byte) 0x03, (byte)nbBlocks);
				cmd = new CommandAPDU(apdu);
				resp = sendAPDU(cmd, DISPLAY);

				respBytes = resp.getBytes();
				lengthWithSW = respBytes.length;
				respLength = lengthWithSW - 2;
				sw1 = respBytes[lengthWithSW - 2] & 0xFF;
				sw2 = respBytes[lengthWithSW - 1] & 0xFF;

				if (sw1 == 0x90 && sw2 == 0x00 && respLength == lastBlockSize) {
					fileContent.write(respBytes, 0, respLength);

					// I write my file
					FileOutputStream outStream = null;
					try {
						outStream = new FileOutputStream("out_" + fileName);
						outStream.write(fileContent.toByteArray());
						System.out.println("[+] File written successfully: out_" + fileName);
					} catch (IOException e) {
						System.err.println("[X] Error: writing the file: " + e.getMessage());
					} finally {
						if (outStream != null) {
							try {
								outStream.close();
							} catch (IOException e) {
								System.err.println("[X] Error: closing the file stream: " + e.getMessage());
							}
						}
					}
				} else {
					System.out.println("[X] Error: reading last block");
					return;
				}
			}

			System.out.println("[+] File content:");
			System.out.println(new String(fileContent.toByteArray()));
		} else {
			System.out.println("[X] Error didn't find index " + index);
		}
	}




	void exit() {
		loop = false;
	}


	void runAction( int choice ) {
		switch( choice ) {
			case 1: cipherFileByCard(); break;
			case 2: uncipherFileByCard(); break;
			case 3: updateCardKey(); break;
			case 4: writeFileToCard(); break;
			case 5: listFiles(); break;
			case 6: readFileByIndex(); break;
			case 0: exit(); break;
			default: System.out.println( "unknown choice!" );
		}
	}


	String readKeyboard() {
		String result = null;

		try {
			BufferedReader input = new BufferedReader( new InputStreamReader( System.in ) );
			result = input.readLine();
		} catch( Exception e ) {}

		return result;
	}


	int readMenuChoice() {
		int result = 0;

		try {
			String choice = readKeyboard();
			result = Integer.parseInt( choice );
		} catch( Exception e ) {}

		System.out.println( "" );

		return result;
	}


	void printMenu() {
		System.out.println( "" );
		System.out.println("6: Read a file by its index");
		System.out.println("5: List files on the card");
		System.out.println("4: Add a new file to the card");
		System.out.println("3: Change the card DES key");
		System.out.println("2: Decrypt a file with DES");
		System.out.println("1: Encrypt a file with DES");
		System.out.println( "0: exit" );
		System.out.print( "--> " );
	}


	void mainLoop() {
		while( loop ) {
			printMenu();
			int choice = readMenuChoice();
			runAction( choice );
		}
	}


	public static void main( String[] args ) throws InterruptedException {
		new TheClient();
	}


}
