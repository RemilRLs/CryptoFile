package applet;


import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;




public class TheApplet extends Applet {

	// PART 1 : STORED FILE

	static final byte READFILEFROMCARD			= (byte)0x10;
	static final byte WRITEFILETOCARD			= (byte)0x09;


	/*

	I made sure to make an implementation where I retain the offsets with variables. In fact this allows me to have
	increased performance to avoid having to dynamically recalculate the positions in my storedFile table each time
	(I had made an implementation with dynamic recalculation but it was too slow) Thanks to this allows me to avoid
	making loops to recalculate each time

	 */

	final static short MAX_FILE_SIZE = (short) 20000;
	static byte[] storedFile = new byte[MAX_FILE_SIZE];
	static short storedFileOffset = 0; // I use this to know where I am in the storedFile array during writing.
	static short currentFileOffset = 0; // To know where my metadata are.
	static short fileCount = 0;
	static final short MAX_FILES = 10;

	final static short BLOC_SIZE = 127;


	private short currentNbBlocks = 0;
	private short currentLastBlockSize = 0;
	private short currentDataOffset = 0;

	// PART 2 :  DES ENCRYPTION AND DECRYPTION

	static final byte UPDATECARDKEY				= (byte)0x14;
	private final static byte ENCRYPT_FILE_DES           	= (byte)0x20;
	private final static byte DECRYPT_FILE_DES           	= (byte)0x21;


	static final byte[] theDESKey =
			new byte[] { (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA };


	// cipher instances
	private Cipher
			cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;


	// key objects

	private Key
			secretDESKey, secretDES2Key, secretDES3Key;


	// "Foo" (name, also sent after termining an operation)
	private byte[] name = { (byte)0x03, (byte)0x46, (byte)0x6F, (byte)0x6F };
	// data's size
	private final static short DTRSIZE = (short)256;//256bytes==2048bits//FOO 8160;//mqos.jpg is 100x20, so...
	// loop variable
	private short i, j, k, x, y;
	// read/write tests array size
	//private final static short WRITINGSIZE = 10;
	// to generate random data
	private final static short RANDOMSIZE = 1000; // <=DTRSIZE
	short offset;
	short length;
	// to perform reading/writing test
	private static final short ARRAY_SIZE = 10;
	private static final short NBWRITEMEM = 100;
	private static final short NBREADMEM = 100;
	private byte[] data;
	private byte[] dataToCipher = {1,2,3,4,5,6,7,8};
	private byte[] ciphered = new byte[8];
	/*
    //size of file, short = byte1 + byte2
    private byte[] fileSize1 = new byte[]{ (byte)0xAB, (byte)0xBC };
    //size of file2, short = byte1 + byte2
    private byte[] fileSize2 = new byte[]{ (byte)0xCD, (byte)0xDE };
    */
	//stack counter
	private byte[] stackCounter = { 0x00 };
	//nb loop DES tests
	private final static short NBTESTSDESCIPHER = 100;
	private final static short NBTESTSDESUNCIPHER = 100;
	/*
    //nb loop RSA tests
    private final static short NBTESTSRSACIPHER = 100;
    private final static short NBTESTSRSAUNCIPHER = 100;
    */
	//private final static short MEMTESTSIZE = 10;
	//VM loop size
	//private final static short VMLOOPSIZE = 30;
	//to test capabilities of the card
	boolean
			pseudoRandom, secureRandom,
			SHA1, MD5, RIPEMD160,
			keyDES, DES_ECB_NOPAD, DES_CBC_NOPAD;


	protected TheApplet() {
		initKeyDES();
		initDES_ECB_NOPAD();

		this.register();
	}

	private void initKeyDES() {
		try {
			secretDESKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
			((DESKey)secretDESKey).setKey(theDESKey,(short)0);
			keyDES = true;
		} catch( Exception e ) {
			keyDES = false;
		}
	}


	private void initDES_ECB_NOPAD() {
		if( keyDES ) try {
			cDES_ECB_NOPAD_enc = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
			cDES_ECB_NOPAD_dec = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
			cDES_ECB_NOPAD_enc.init( secretDESKey, Cipher.MODE_ENCRYPT );
			cDES_ECB_NOPAD_dec.init( secretDESKey, Cipher.MODE_DECRYPT );
			DES_ECB_NOPAD = true;
		} catch( Exception e ) {
			DES_ECB_NOPAD = false;
		}
	}


	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new TheApplet();
	}


	public boolean select() {
		return true;
	}


	public void deselect() {
	}



	public void process(APDU apdu) throws ISOException {
		if( selectingApplet() == true )
			return;

		byte[] buffer = apdu.getBuffer();

		switch( buffer[1] ) 	{
			case DECRYPT_FILE_DES:
				cipherGeneric(apdu, cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES);
				break;
			case ENCRYPT_FILE_DES:
				cipherGeneric(apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES);
				break;
			case UPDATECARDKEY:
				updateCardKey(apdu);
				break;
			case READFILEFROMCARD:
				readFileFromCard(apdu);
				break;
			case WRITEFILETOCARD:
				writeFileToCard(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Function to change the DES key.
	 * @param apdu APDU to change the DES key
	 */
	void updateCardKey( APDU apdu ) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();

		if(bytesRead != 8) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		byte[] newKey = new byte[8];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, newKey, (short)0, (short)8);
		((DESKey)secretDESKey).setKey(newKey, (short)0);
	}

	/**
	 * Function to encrypt or decrypt a file with DES
	 * @param apdu APDU to encrypt or decrypt a fi
	 * @param cipher type of cipher to use (in my case DES)
	 * @param keyLength length of the key
	 *@param cipherMode mode of the cipher (encrypt or decrypt)
	 */
	private void cipherGeneric(APDU apdu, Cipher cipher, short keyLength) {
		byte[] buffer = apdu.getBuffer();

		short bytesReadToCipher = apdu.setIncomingAndReceive();



		short sizeAfterCipher = cipher.doFinal(
				buffer,
				ISO7816.OFFSET_CDATA,
				bytesReadToCipher,
				buffer,                //  Where I put my result (ciphertext)
				(short)0
		);

		apdu.setOutgoingAndSend((short)0, sizeAfterCipher);
	}

	/**
	 * Function to write a file to the card
	 * @param apdu APDU to write like metadata, blocks and last block
	 */
	void writeFileToCard(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		byte p1 = buffer[ISO7816.OFFSET_P1];

		switch (p1) {
			case 0x01: // I write metadata with initialization of nbBlocks and lastBlockSize to 0
				if (fileCount >= MAX_FILES) {
					ISOException.throwIt(ISO7816.SW_FILE_FULL);
				}

				byte fileNameLength = buffer[ISO7816.OFFSET_CDATA];

				// With metadata I store the size of the name file and the name file
				storedFile[storedFileOffset++] = fileNameLength;
				Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), storedFile, storedFileOffset, fileNameLength);
				storedFileOffset = (short) (storedFileOffset + fileNameLength);

				// I also init the nbBlocks and lastBlockSize to 0
				Util.setShort(storedFile, storedFileOffset, (short) 0);
				storedFileOffset = (short) (storedFileOffset + 2);
				Util.setShort(storedFile, storedFileOffset, (short) 0);
				storedFileOffset = (short) (storedFileOffset + 2);

				currentFileOffset = storedFileOffset;  // Where is my metadata
				break;

			case 0x02: // For writing a block

				/*
				Note :
					Although P2 contains the block identifier (trunkID), it is not used in my case. This is only used in the readFile function to know where I am in the file
					Maybe I will use it there to write a specific block but for now it is not used

					Reason: The current approach is based on a global counter that I named storedFileOffset and locally currentFileOffset which advances sequentially as I write my data.
					In my opinion, this method guarantees simple management and greatly reduces complexity

					Because if I had to use P2 I would have had to make a form of directory which would add too much complexity in order to avoid collisions
					between files and to always ensure that the blocks are written in the right positions
				 */


				if ((short) (bytesRead + storedFileOffset) > MAX_FILE_SIZE) { // I'm still checking if I'm not going to overflow
					ISOException.throwIt(ISO7816.SW_FILE_FULL);
				}

				Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storedFile, storedFileOffset, bytesRead);
				storedFileOffset = (short) (storedFileOffset + bytesRead); // I keep going in my storedFile array


				short nbBlocks = Util.getShort(storedFile, (short) (currentFileOffset - 4));
				Util.setShort(storedFile, (short) (currentFileOffset - 4), (short) (nbBlocks + 1));

				break;

			case 0x03: // My last block
				if ((short) (bytesRead + storedFileOffset) > MAX_FILE_SIZE) {
					ISOException.throwIt(ISO7816.SW_FILE_FULL);
				}

				Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storedFile, storedFileOffset, bytesRead);
				storedFileOffset = (short) (storedFileOffset + bytesRead);

				Util.setShort(storedFile, (short) (currentFileOffset - 2), bytesRead); // Last block size
				fileCount++;
				break;

			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}


	/**
	 * Function to read operations from the card
	 *
	 * I have 4 operations :
	 * - P1 = 0x01 : Get the list of files
	 * - P1 = 0x02 : Get metadata of a specific file byt its name (I think I'm going to delete that one TODO)
	 * - P1 = 0x03 : Get a block of a file
	 * - P1 = 0x04 : Get the metadata by index
	 * @param apdu APDU command for the request (reading file)
	 */
	void readFileFromCard(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];

		short index;
		short offset = 0;
		short searchOffset = 0;

		switch (p1) {
			case 0x01: // list all the files stored in storedFile
				apdu.setOutgoing();
				short responseOffset = 0;
				// I loop through all the files stored in my storedFile array
				for (short i = 0; i < fileCount; i++) {
					// Index of the file

					buffer[responseOffset++] = (byte) i;

					// Length of the file name
					byte fileNameLength = storedFile[offset];
					buffer[responseOffset++] = fileNameLength;
					offset++;

					// File name
					Util.arrayCopy(storedFile, offset, buffer, responseOffset, fileNameLength);
					responseOffset += fileNameLength;
					offset += fileNameLength;

					// Size (to know the size of the file client side)
					short nbBlocks = Util.getShort(storedFile, offset);
					offset += 2;
					short lastBlockSize = Util.getShort(storedFile, offset);
					offset += 2;


					short totalSize = (short) (nbBlocks * BLOC_SIZE + lastBlockSize);


					buffer[responseOffset++] = (byte) (totalSize >> 8);
					buffer[responseOffset++] = (byte) (totalSize & 0xFF);

					// I go to the next file

					offset += totalSize;
				}

				// I had to use this because if I use setOutgoingAndSend it doesn't work
				// I have a 6F 00 error
				apdu.setOutgoingLength(responseOffset);
				apdu.sendBytes((short) 0, responseOffset);
				break;

			case 0x03: // Retrieve a specific block by it id (trunk ID)

				short blockId = (short)(p2 & 0xFF); // The trunk ID.

				if (blockId < currentNbBlocks) {
					short blockStart = (short)(currentDataOffset + blockId * BLOC_SIZE);
					Util.arrayCopy(storedFile, blockStart, buffer, (short)0, BLOC_SIZE);
					apdu.setOutgoingAndSend((short)0, BLOC_SIZE);
				} else if (blockId == currentNbBlocks) { // My last block
					short blockStart = (short)(currentDataOffset + currentNbBlocks * BLOC_SIZE);
					Util.arrayCopy(storedFile, blockStart, buffer, (short)0, currentLastBlockSize);
					apdu.setOutgoingAndSend((short)0, currentLastBlockSize);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				break;

			case 0x04: // I read the file P2 is the index of my file
				short fileIndex = (short) (p2 & 0xFF);
				if (fileIndex >= fileCount) {
					ISOException.throwIt((short)0x6A83); // Didn't find the file because out of bounds
				}

				// I go through all my file stored to find it.
				searchOffset = 0;
				for (short i = 0; i < fileIndex; i++) {
					byte curFileNameLength = storedFile[searchOffset];
					searchOffset++;
					searchOffset += curFileNameLength;
					short tmpNbBlocks = Util.getShort(storedFile, searchOffset);
					searchOffset += 2;
					short tmpLastBlockSize = Util.getShort(storedFile, searchOffset);
					searchOffset += 2;
					searchOffset += (short)(tmpNbBlocks * BLOC_SIZE + tmpLastBlockSize);
				}

				// Now I'm in front of my file
				byte curFileNameLength = storedFile[searchOffset];
				searchOffset++;
				byte[] fileName = new byte[curFileNameLength];
				Util.arrayCopy(storedFile, searchOffset, fileName, (short)0, curFileNameLength);
				searchOffset += curFileNameLength;
				currentNbBlocks = Util.getShort(storedFile, searchOffset);
				searchOffset += 2;
				currentLastBlockSize = Util.getShort(storedFile, searchOffset);
				searchOffset += 2;

				currentDataOffset = searchOffset;

				// I send the number of blocks and the last block size and also the name of the file.


				Util.arrayCopy(fileName, (short) 0, buffer, (short) 0, curFileNameLength);
				offset = (short) curFileNameLength;

				// NbBlocks (I put it after the name of the file)
				buffer[offset++] = (byte) (currentNbBlocks >> 8);
				buffer[offset++] = (byte) (currentNbBlocks & 0xFF);

				// LastBlockSize
				buffer[offset++] = (byte) (currentLastBlockSize >> 8);
				buffer[offset++] = (byte) (currentLastBlockSize & 0xFF);

				apdu.setOutgoingAndSend((short) 0, (short) (4 + curFileNameLength));
				break;

			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
