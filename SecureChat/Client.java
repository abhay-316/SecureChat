import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.*;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client  {

	// for I/O
	private ObjectInputStream sInput;		// to read from the socket
	private ObjectOutputStream sOutput;		// to write on the socket
	private Socket socket;

	// if I use a GUI or not
	private ClientGUI cg;
	
	// the server, the port and the username
	private String server, username;
	private int port;
	// connected users' id list
	private List<String> active_users;
	private String session_key;
	private String rsa_pri_key = "privkey.pem";
	private String rsa_pub_key = "pubkey.pem";
	// identification get from server
	private String id;
	private String whiper_id;
	private boolean whisper_talk = false;
	private CipherInterface des_cipher;
	private CipherInterface rsa_cipher;
	// to display time
	private SimpleDateFormat sdf;
	/*
	 *  Constructor called by console mode
	 *  server: the server address
	 *  port: the port number
	 *  username: the username
	 */
	Client(String server, int port, String username) {
		// which calls the common constructor with the GUI set to null
		this(server, port, username, null);
	}

	/*
	 * Constructor call when used from a GUI
	 * in console mode the ClienGUI parameter is null
	 */
	Client(String server, int port, String username, ClientGUI cg) {
		this.server = server;
		this.port = port;
		this.username = username;
		// save if we are in GUI mode or not
		this.cg = cg;
		this.active_users = new ArrayList<String>();
		// DES cipher
		des_cipher = new DES();
		// RSA cipher
		rsa_cipher = new RSA_433();
		// time formater
		sdf = new SimpleDateFormat("HH:mm:ss");
	}
	
	/*
	 * To start the dialog
	 */
	public boolean start() {
		// try to connect to the server
		try {
			socket = new Socket(server, port);
		} 
		// if it failed not much I can so
		catch(Exception ec) {
			display("Error connectiong to server:" + ec);
			return false;
		}
		
		String msg = "Connection accepted " + socket.getInetAddress() + ":" + socket.getPort();
		display(msg);
	
		/* Creating both Data Stream */
		try
		{
			sInput  = new ObjectInputStream(socket.getInputStream());
			sOutput = new ObjectOutputStream(socket.getOutputStream());
		}
		catch (IOException eIO) {
			display("Exception creating new Input/output Streams: " + eIO);
			return false;
		}

		// creates the Thread to listen from the server 
		new ListenFromServer().start();
		// Send our username to the server this is the only message that we
		// will send as a String. All other messages will be ChatMessage objects
		try
		{
			sOutput.writeObject(username);
		}
		catch (IOException eIO) {
			display("Exception doing login : " + eIO);
			disconnect();
			return false;
		}
		// success we inform the caller that it worked
		return true;
	}

	/*
	 * To send a message to the console or the GUI
	 */
	private void display(String msg) {
		if(cg == null)
			System.out.println(msg);      // println in console mode
		else
			cg.append(msg + "\n");		// append to the ClientGUI JTextArea (or whatever)
	}
	
	/*
	 * Send message to chat room or online user
	 */
	void processMessage(String msg){
		ChatMessage cm;
		if(whisper_talk){
			// send encrypted message to an online user (only the destination user could decrypt and see)
			cm = new ChatMessage(ChatMessage.WHISPER, username);
			cm.setRoute(this.id, this.whiper_id);
			// Encode with Base64
			String encoded_msg = null;
			encoded_msg = Base64.getEncoder().withoutPadding().encodeToString(msg.getBytes());
			// Encrypt with DES
			String content = encrypMsg(encoded_msg);
			cm.setContent(content);
		}else{
			// send an plain text to chat room (everyone body could see)
			cm = new ChatMessage(ChatMessage.MESSAGE, msg);
		}
		sendMessage(cm);
	}
	
	/*
	 * To send a message to the server
	 */
	void sendMessage(ChatMessage msg) {
		try {
			sOutput.writeObject(msg);
		}
		catch(IOException e) {
			display("Exception writing to server: " + e);
		}
	}

	/*
	 * When something goes wrong
	 * Close the Input/Output streams and disconnect not much to do in the catch clause
	 */
	private void disconnect() {
		try { 
			if(sInput != null) sInput.close();
		}
		catch(Exception e) {} // not much else I can do
		try {
			if(sOutput != null) sOutput.close();
		}
		catch(Exception e) {} // not much else I can do
        try{
			if(socket != null) socket.close();
		}
		catch(Exception e) {} // not much else I can do
		
		// inform the GUI
		if(cg != null)
			cg.connectionFailed();
			
	}
	/*
	 * To start the Client in console mode use one of the following command
	 * > java Client
	 * > java Client username
	 * > java Client username portNumber
	 * > java Client username portNumber serverAddress
	 * at the console prompt
	 * If the portNumber is not specified 1500 is used
	 * If the serverAddress is not specified "localHost" is used
	 * If the username is not specified "Anonymous" is used
	 * > java Client 
	 * is equivalent to
	 * > java Client Anonymous 1500 localhost 
	 * are eqquivalent
	 * 
	 * In console mode, if an error occurs the program simply stops
	 * when a GUI id used, the GUI is informed of the disconnection
	 */
	public static void main(String[] args) {
		// default values
		int portNumber = 1500;
		String serverAddress = "localhost";
		String userName = "Anonymous";

		// depending of the number of arguments provided we fall through
		switch(args.length) {
			// > javac Client username portNumber serverAddr
			case 3:
				serverAddress = args[2];
			// > javac Client username portNumber
			case 2:
				try {
					portNumber = Integer.parseInt(args[1]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
					return;
				}
			// > javac Client username
			case 1: 
				userName = args[0];
			// > java Client
			case 0:
				break;
			// invalid number of arguments
			default:
				System.out.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
			return;
		}
		// create the Client object
		Client client = new Client(serverAddress, portNumber, userName);
		// test if we can start the connection to the Server
		// if it failed nothing we can do
		if(!client.start())
			return;
		
		// wait for messages from user
		Scanner scan = new Scanner(System.in);
		// loop forever for message from the user
		while(true) {
			System.out.print("> ");
			// read message from user
			String msg = scan.nextLine();
			// logout if message is LOGOUT
			if(msg.equalsIgnoreCase("LOGOUT")) {
				client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, "pwd"));
				// break to do the disconnect
				break;
			}
			// message WhoIsIn
			else if(msg.equalsIgnoreCase("WHOISIN")) {
				client.active_users.removeAll(null);
				client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, ""));
			}
			else {				// default to ordinary message
				client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, msg));
			}
		}
		// done disconnect
		client.disconnect();	
	}
	
	/*
	 * start whisper
	 */
	public void whisper(){
		display("whisper");
		if(!whisper_talk){
			String des = null;
			String src = null;
			// find an online user to chat with
			for(String user: active_users){
				//display("user_id="+user);
				if(!user.equalsIgnoreCase(this.id)){
					des = user;
				}
			}
			if(des == null){
				display("can not find another online user");
				return;
			}
			src = this.id;
			// create request message
			ChatMessage msg = new ChatMessage(ChatMessage.WHISPER_REQUEST, "");
			msg.setRoute(src, des);
			// send request to server
			sendMessage(msg);
		}else{
			// handle later
		}
	}
	
	/*
	 * parse chat message 
	 */
	private void parseMessage(ChatMessage msg){
		String display_msg;
		switch(msg.getType()){
		case ChatMessage.LOGIN:
			this.id = msg.getContent();
			break;
		case ChatMessage.WHOISIN:
			active_users.add(msg.getContent());
			display_msg = msg.getMessage();
			// if console mode print the message and add back the prompt
			if(cg == null) {
				System.out.println(display_msg);
				System.out.print("> ");
			}
			else {
				cg.append(display_msg);
			}
			break;
		case ChatMessage.WHISPER_REQUEST:
			// Whisper message comes from sever, is a session key
			session_key = decryptKey(msg.getContent());
//			session_key = msg.getContent();
			display("key:"+msg.getContent());
			display("decrypted key:"+session_key);
			// set key to DES cipher
			try {
				des_cipher.setKey(session_key);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			whiper_id = msg.getDestination();
			whisper_talk = true;
			break;
		case ChatMessage.WHISPER:
			parseWhisperMsg(msg);
			break;
		case ChatMessage.MESSAGE:
			display_msg = msg.getMessage();
			// if console mode print the message and add back the prompt
			if(cg == null) {
				System.out.println(display_msg);
				System.out.print("> ");
			}
			else {
				cg.append(display_msg);
			}
			break;
		}
	}
	
	/*
	 * Whisper Message
	 */
	private void parseWhisperMsg(ChatMessage msg){
		// Whisper message comes from another user, decryp and display it
		// decrypt msg with DES
		String encoded_msg = decryptMsg(msg.getContent());
		// decode msg with Base64
		String display_msg = null;
		display_msg = new String(Base64.getDecoder().decode(encoded_msg));
//		display_msg = decryptMsg(msg.getContent());
		String time = sdf.format(new Date());
		display(time + " " + msg.getMessage() + ": " + display_msg);
	}
	
	/*
	 * Decryt session key with private key 
	 */
	private String decryptKey(String cipherkey){
		String key = null;
		try {
			rsa_cipher.setKey(rsa_pri_key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			key = rsa_cipher.decrypt(cipherkey);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return key;
	}
	
	/*
	 * Decrypt message with DES
	 */
	private String decryptMsg(String ciphertext){
		String plaintext = null;
		try {
			plaintext = des_cipher.decrypt(ciphertext);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return plaintext;
	}
	
	/*
	 * encryt message with DES 
	 */
	private String encrypMsg(String plaintext){
		String ciphertext = null;
		try {
			ciphertext = des_cipher.encrypt(plaintext);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ciphertext;
	}
	/*
	 * a class that waits for the message from the server and append them to the JTextArea
	 * if we have a GUI or simply System.out.println() it in console mode
	 */
	class ListenFromServer extends Thread {

		public void run() {
			while(true) {
				try {
//					String msg = (String) sInput.readObject();
					ChatMessage msgObject = (ChatMessage) sInput.readObject();
					//parse Message
					parseMessage(msgObject);
				}
				catch(IOException e) {
					display("Server has close the connection: " + e);
					if(cg != null) 
						cg.connectionFailed();
					
					break;
				}
				// can't happen with a String object but need the catch anyhow
				catch(ClassNotFoundException e2) {
				}
			}
		}
	}
}
