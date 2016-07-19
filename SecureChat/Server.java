import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
	// a unique ID for each connection
	private static int uniqueId;
	// an ArrayList to keep the list of the Client
	private ArrayList<ClientThread> al;
	// if I am in a GUI
	private ServerGUI sg;
	// to display time
	private SimpleDateFormat sdf;
	// the port number to listen for connection
	private int port;
	// the boolean that will be turned of to stop the server
	private boolean keepGoing;
	

	/*
	 *  server constructor that receive the port to listen to for connection as parameter
	 *  in console
	 */
	public Server(int port) {
		this(port, null);
	}
	
	public Server(int port, ServerGUI sg) {
		// GUI or not
		this.sg = sg;
		// the port
		this.port = port;
		// to display hh:mm:ss
		sdf = new SimpleDateFormat("HH:mm:ss");
		// ArrayList for the Client list
		al = new ArrayList<ClientThread>();
	}
	
	public void start() {
		keepGoing = true;
		/* create socket server and wait for connection requests */
		try 
		{
			// the socket used by the server
			ServerSocket serverSocket = new ServerSocket(port);

			// infinite loop to wait for connections
			while(keepGoing) 
			{
				// format message saying we are waiting
				display("Server waiting for Clients on port " + port + ".");
				
				Socket socket = serverSocket.accept();  	// accept connection
				// if I was asked to stop
				if(!keepGoing)
					break;
				ClientThread t = new ClientThread(socket);  // make a thread of it
				al.add(t);									// save it in the ArrayList
				t.start();
				// notify user's id
				t.notifyId();
			}
			// I was asked to stop
			try {
				serverSocket.close();
				for(int i = 0; i < al.size(); ++i) {
					ClientThread tc = al.get(i);
					try {
					tc.sInput.close();
					tc.sOutput.close();
					tc.socket.close();
					}
					catch(IOException ioE) {
						// not much I can do
					}
				}
			}
			catch(Exception e) {
				display("Exception closing the server and clients: " + e);
			}
		}
		// something went bad
		catch (IOException e) {
            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
			display(msg);
		}
	}		
    /*
     * For the GUI to stop the server
     */
	protected void stop() {
		keepGoing = false;
		// connect to myself as Client to exit statement 
		// Socket socket = serverSocket.accept();
		try {
			new Socket("localhost", port);
		}
		catch(Exception e) {
			// nothing I can really do
		}
	}
	/*
	 * Display an event (not a message) to the console or the GUI
	 */
	private void display(String msg) {
		String time = sdf.format(new Date()) + " " + msg;
		if(sg == null)
			System.out.println(time);
		else
			sg.appendEvent(time + "\n");
	}
	/*
	 * Display an message at chat room
	 */
	private void displayInChatRoom(String msg){
		String time = sdf.format(new Date()) + " " + msg;
		if(sg == null)
			System.out.println(time);
		else
			sg.appendRoom(time + "\n");
	}
	/*
	 *  to broadcast a message to all Clients
	 */
	private synchronized void broadcast(String message) {
		// add HH:mm:ss and \n to the message
		String time = sdf.format(new Date());
		String messageLf = time + " " + message + "\n";
		// display message on console or GUI
		if(sg == null)
			System.out.print(messageLf);
		else
			sg.appendRoom(messageLf);     // append in the room window
		
		// we loop in reverse order in case we would have to remove a Client
		// because it has disconnected
		for(int i = al.size(); --i >= 0;) {
			ClientThread ct = al.get(i);
			// try to write to the Client if it fails remove it from the list
			ChatMessage msg = new ChatMessage(ChatMessage.MESSAGE, messageLf);
			if(!ct.sendMsg(msg)){
				al.remove(i);
				display("Disconnected Client " + ct.username + " removed from list.");		
			}
//			if(!ct.writeMsg(messageLf)) {
//				al.remove(i);
//				display("Disconnected Client " + ct.username + " removed from list.");
//			}
		}
	}

	// for a client who logoff using the LOGOUT message
	synchronized void remove(int id) {
		// scan the array list until we found the Id
		for(int i = 0; i < al.size(); ++i) {
			ClientThread ct = al.get(i);
			// found it
			if(ct.id == id) {
				al.remove(i);
				return;
			}
		}
	}
	
	/*
	 *  To run as a console application just open a console window and: 
	 * > java Server
	 * > java Server portNumber
	 * If the port number is not specified 1500 is used
	 */ 
	public static void main(String[] args) {
		// start server on port 1500 unless a PortNumber is specified 
		int portNumber = 1500;
		switch(args.length) {
			case 1:
				try {
					portNumber = Integer.parseInt(args[0]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Server [portNumber]");
					return;
				}
			case 0:
				break;
			default:
				System.out.println("Usage is: > java Server [portNumber]");
				return;
				
		}
		// create a server object and start it
		Server server = new Server(portNumber);
		server.start();
	}
	
	/*
	 * Generate DES session key for whisper users
	 */
	String generateSessionKey(){
		String key = null;
		try{
		    /**
		      * Create an instance of a key generator; a class used
		      * for generating DES encryption keys.
		      */
		    KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
		   
		    /**
		     * Generate a DES key
		     */
		    SecretKey myDesKey = keygenerator.generateKey();;    
		    key = Base64.getEncoder().encodeToString(myDesKey.getEncoded());
		    
		}catch(Exception e){
			e.printStackTrace();
		}
		// return session key
		return key;
	}

	/*
	 * Distribute session key to whisper users
	 */
	private synchronized void distributeKey(String key, String src, String des){
		int des_id = Integer.parseInt(des);
		int src_id = Integer.parseInt(src);
		for(int i = 0; i < al.size(); ++i){
			ClientThread ct = al.get(i);
			// found whisper users 
			if(ct.id == des_id || ct.id == src_id){
				//create message contains session key
				ChatMessage cm = new ChatMessage(ChatMessage.WHISPER_REQUEST, "distribute session key");
				cm.setContent(key);
				if(ct.id == des_id){
					cm.setRoute(des, src);
				}else{
					cm.setRoute(src, des);
				}
				// send message
				ct.sendMsg(cm);
			}
		}
	}
	/*
	 * Distribute message to whisper users
	 */
	private synchronized void distributeMsg(ChatMessage cm){
		int des_id = Integer.parseInt(cm.getDestination());
		int src_id = Integer.parseInt(cm.getSource());
		for(int i = 0; i < al.size(); ++i){
			ClientThread ct = al.get(i);
			// found whisper users 
			if(ct.id == des_id || ct.id == src_id){
				// send message
				ct.sendMsg(cm);
			}
		}
	}
	
	/** One instance of this thread will run for each client */
	class ClientThread extends Thread {
		// the socket where to listen/talk
		Socket socket;
		ObjectInputStream sInput;
		ObjectOutputStream sOutput;
		// my unique id (easier for deconnection)
		int id;
		// the Username of the Client
		String username;
		// the only type of message a will receive
		ChatMessage cm;
		// the date I connect
		String date;
		// RSA public key 
		String rsa_pub_key = "pubkey.pem";
		// Constructor
		ClientThread(Socket socket) {
			// a unique id
			id = ++uniqueId;
			this.socket = socket;
			/* Creating both Data Stream */
			System.out.println("Thread trying to create Object Input/Output Streams");
			try
			{
				// create output first
				sOutput = new ObjectOutputStream(socket.getOutputStream());
				sInput  = new ObjectInputStream(socket.getInputStream());
				// read the username
				username = (String) sInput.readObject();
				display(username + " just connected.");
			}
			catch (IOException e) {
				display("Exception creating new Input/output Streams: " + e);
				return;
			}
			// have to catch ClassNotFoundException
			// but I read a String, I am sure it will work
			catch (ClassNotFoundException e) {
			}
            date = new Date().toString() + "\n";
		}

		// what will run forever
		public void run() {
			// to loop until LOGOUT
			boolean keepGoing = true;
			while(keepGoing) {
				// read a String (which is an object)
				try {
					cm = (ChatMessage) sInput.readObject();
				}
				catch (IOException e) {
					display(username + " Exception reading Streams: " + e);
					break;				
				}
				catch(ClassNotFoundException e2) {
					break;
				}
				// the messaage part of the ChatMessage
				String message = cm.getMessage();

				// Switch on the type of message receive
				switch(cm.getType()) {

				case ChatMessage.MESSAGE:
					broadcast(username + ": " + message);
					break;
				case ChatMessage.LOGOUT:
					display(username + " disconnected with a LOGOUT message.");
					keepGoing = false;
					break;
				case ChatMessage.WHOISIN:
					// List of the users
					String title = "List of the users connected at " + sdf.format(new Date()) + "\n";
					sendMsg(new ChatMessage(ChatMessage.MESSAGE, title));
					//writeMsg("List of the users connected at " + sdf.format(new Date()) + "\n");
					// scan al the users connected
					for(int i = 0; i < al.size(); ++i) {
						ClientThread ct = al.get(i);
						//writeMsg((i+1) + ") " + ct.username + " since " + ct.date);
						//message
						String display_msg = (i+1) + ") " + ct.username + " since " + ct.date;
						//set id and user name as content
						String content = ""+ct.id;
						ChatMessage msg = new ChatMessage(ChatMessage.WHOISIN, display_msg);
						msg.setContent(content);
						sendMsg(msg);
					}
					break;
				case ChatMessage.WHISPER:
					// display encrypted message
					displayInChatRoom(username + ": " + cm.getContent());
					// distribute message to destination
					distributeMsg(cm);
					break;
				case ChatMessage.WHISPER_REQUEST:
					// generate session key
					String session_key = generateSessionKey();
//					String session_key = "0123456789abcdef";
					// encrypt session key with RSA
					String encrypted_key = encryptWithRSA(session_key);
					// distribute session key to whisper users
					distributeKey(encrypted_key, cm.getDestination(), cm.getSource());
					break;
				}
			}
			// remove myself from the arrayList containing the list of the
			// connected Clients
			remove(id);
			close();
		}
		
		// try to close everything
		private void close() {
			// try to close the connection
			try {
				if(sOutput != null) sOutput.close();
			}
			catch(Exception e) {}
			try {
				if(sInput != null) sInput.close();
			}
			catch(Exception e) {};
			try {
				if(socket != null) socket.close();
			}
			catch (Exception e) {}
		}

		/*
		 * Write a String to the Client output stream
		 */
		private boolean writeMsg(String msg) {
			// if Client is still connected send the message to it
			if(!socket.isConnected()) {
				close();
				return false;
			}
			// write the message to the stream
			try {
				sOutput.writeObject(msg);
			}
			// if an error occurs, do not abort just inform the user
			catch(IOException e) {
				display("Error sending message to " + username);
				display(e.toString());
			}
			return true;
		}
		/*
		 * notify user's id
		 */
		private void notifyId(){
			ChatMessage msg = new ChatMessage(ChatMessage.LOGIN, "notify id");
			String identification  = String.valueOf(id);
			msg.setContent(identification);
			sendMsg(msg);
		}
		/*
		 * Send a Message Object to Client
		 */
		private boolean sendMsg(ChatMessage msg){
			// if Client is still connected send the message to it
			if(!socket.isConnected()) {
				close();
				return false;
			}
			// write the message to the stream
			try {
				sOutput.writeObject(msg);
			}
			// if an error occurs, do not abort just inform the user
			catch(IOException e) {
				display("Error sending message to " + username);
				display(e.toString());
			}
			return true;
		}
		/*
		 * Encrypt session key with RSA
		 */
		private String encryptWithRSA(String plaintext){
			String encrypted_key = null;
			// create RSA cipher
			RSA_433 cipher = new RSA_433();
			// set public key for encryption
			try {
				cipher.setKey(rsa_pub_key);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// encrypt with RSA
			try {
				encrypted_key = cipher.encrypt(plaintext);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return encrypted_key;
		}
	}
}

