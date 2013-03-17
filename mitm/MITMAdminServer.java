/**
 * CS255 project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;

class MITMAdminServer implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    
    public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
	MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
				
	m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
	m_engine = engine;
    }

    public void run() {
	System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
	while( true ) {
	    try {
		m_socket = m_serverSocket.accept();

		byte[] buffer = new byte[40960];

		Pattern userPwdPattern =
		    Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
		
		BufferedInputStream in =
		    new BufferedInputStream(m_socket.getInputStream(),
					    buffer.length);

		// Read a buffer full.
		int bytesRead = in.read(buffer);

		String line =
		    bytesRead > 0 ?
		    new String(buffer, 0, bytesRead) : "";

		Matcher userPwdMatcher =
		    userPwdPattern.matcher(line);

		// parse username and pwd
		if (userPwdMatcher.find()) {
		    String password = userPwdMatcher.group(1);
		    //begin Borui Wang implementation
		    // TODO(cs255): authenticate the user
		    // System.out.println(password);
		    
		    try {
				String strLine = MITMServerInfo.admin_key_info;
				// System.out.println(strLine);
				String hash_salt = strLine.split(" ")[0];
				String hash_value = strLine.split(" ")[1];
			    String hash_verify = BCrypt.hashpw(password, hash_salt);
				// System.out.println("PWD salt:"+hash_salt);
				// System.out.println("PWD hash value:"+hash_value);
			    // System.out.println("PWD hash verify:"+hash_verify);
			    // if authenticated, do the command
			    if( hash_value.equals(hash_verify) ) {
					String command = userPwdMatcher.group(2);
					String commonName = userPwdMatcher.group(3);
					doCommand( command );
			    }else{
			    	sendString("Invalid password");
			    	m_socket.close();
			    }
			    
			} catch (Exception e) {
				System.err.println("\n" + "Error: " + e.getMessage());
			}
		    //end Borui Wang implementation
		}	
	    }
	    catch( InterruptedIOException e ) {
	    }
	    catch( Exception e ) {
		e.printStackTrace();
	    }
	}
    }

    private void sendString(final String str) throws IOException {
	PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
	writer.println(str);
	writer.flush();
    }
    
    private void doCommand( String cmd ) throws IOException {
    // begin Borui Wang implementation
	// TODO(cs255): instead of greeting admin client, run the indicated command
    if(cmd.equals("shutdown")){
    	sendString("Shutting down server..");
    	m_socket.close();
    	System.exit(0);
    }else if(cmd.equals("stats")){
    	sendString("Proxy server has received such number of requests: "+String.valueOf(MITMServerInfo.proxy_count));
    	m_socket.close();
    }else{
    	sendString("How are you Admin Client ! You have not issued a command, I don't know what to do!");
    	m_socket.close();
    }
	//end Borui Wang implementation
    }

}
