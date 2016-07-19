
import java.io.*;
/*
 * This class defines the different type of messages that will be exchanged between the
 * Clients and the Server. 
 * When talking from a Java Client to a Java Server a lot easier to pass Java objects, no 
 * need to count bytes or to wait for a line feed at the end of the frame
 */
public class ChatMessage implements Serializable {

	protected static final long serialVersionUID = 1112122200L;

	// The different types of message sent by the Client
	// WHOISIN to receive the list of the users connected
	// MESSAGE an ordinary message
	// LOGOUT to disconnect from the Server
	// WHISPER talk to another user secretly
	static final int WHOISIN = 0, MESSAGE = 1, LOGOUT = 2, WHISPER_REQUEST = 3, WHISPER = 4, LOGIN = 5;
	private int type;
	private String destination;
	private String source;
	private String message;
	private String content;
	
	// constructor
	ChatMessage(int type, String message) {
		this.type = type;
		this.message = message;
	}
	
	public void setContent(String content){
		this.content = content;
	}
	
	public void setRoute(String src, String des){
		this.destination = des;
		this.source = src;
	}
	// getters
	int getType() {
		return type;
	}
	
	String getMessage() {
		return message;
	}
	
	String getContent(){
		return content;
	}
	
	String getDestination(){
		return destination;
	}
	
	String getSource(){
		return source;
	}
}

