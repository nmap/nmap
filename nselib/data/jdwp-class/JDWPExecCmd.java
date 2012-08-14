import java.io.*;

/* This is the JDWPExecCmd source used for jdwp-exec script to execute 
 * a command on the remote system. 
 *
 * It just executes the shell command passed as string argument to
 * run() function and returns its output.
 * 
 * Compile simply with:
 * javac JDWPExecCmd.java (should be in the nselib/data/ directory).
 *
 * author = "Aleksandar Nikolic" 
 * license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
*/

public class JDWPExecCmd {
    public static String run(String cmd) {
		String result = cmd + " output:\n";	
		try{
			Process p = Runtime.getRuntime().exec(cmd);  
			BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));  
			String line = null;  
			while ((line = in.readLine()) != null) {  
				result += line.trim()+"\n"; 
			}
			result += "\n";
		}catch(Exception ex){
			}
		return result;
	}
}