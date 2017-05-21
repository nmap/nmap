import java.io.*;
import java.util.Date;
/* This is the JDWPSystemInfo source used for jdwp-info script to get remote 
 * system information.
 *
 * Compile simply with:
 * javac JDWPSystemInfo.java (should be in the nselib/data/jdwp-class directory).
 *
 * author = "Aleksandar Nikolic" 
 * license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
*/

public class JDWPSystemInfo {
    public static String run() {
		String result = "";	
		result += "Available processors: " +  Runtime.getRuntime().availableProcessors() + "\n";
		result += "Free memory: " + Runtime.getRuntime().freeMemory() + "\n";
		File[] roots = File.listRoots();
		for (File root : roots) {
			result += "File system root: " + root.getAbsolutePath() + "\n";
			result += "Total space (bytes): " + root.getTotalSpace() + "\n";
			result += "Free space (bytes): " + root.getFreeSpace() + "\n";
		}
		result += "Name of the OS: " + System.getProperty("os.name") + "\n";
		result += "OS Version : " + System.getProperty("os.version") + "\n";
		result += "OS patch level : " + System.getProperty("sun.os.patch.level") + "\n";
		result += "OS Architecture: " + System.getProperty("os.arch") + "\n";		
		result += "Java version: " + System.getProperty("java.version") + "\n";		
		result += "Username: " + System.getProperty("user.name") + "\n";		
		result += "User home: " + System.getProperty("user.home") + "\n";		
		Date dateNow = new Date();
		result += "System time: " + dateNow + "\n";		
		
		return result;
	}
	
	public static void main(String[] args){
		System.out.println(run());
	}
	
}
