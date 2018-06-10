package com;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

/**
 * 
 * <b>Description : </b></br>This will detect if any intrusion happen to
 * paxpharma and record,report and throw error
 * 
 * @author prasanna_awachat
 * 
 */
public class IntrusionDetector {

	// private static final Logger LOGGER = Logger
	// .getLogger(IntrusionDetector.class);

	private static Pattern[] patterns = new Pattern[] {
			Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
			Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
			Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE
					| Pattern.MULTILINE | Pattern.DOTALL),
			Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
			//Pattern.compile("/[=]/g", Pattern.CASE_INSENSITIVE),
			Pattern.compile("(.*?)[=](.*?)", Pattern.CASE_INSENSITIVE)
			};
	
	

	// public IntrusionDetector() {
	//
	// }

	/**
	 * 
	 * check for attack.
	 * 
	 * @param inputs
	 * @param loggedInUserName
	 * @return true/false
	 */

	public boolean checkAttacks(String[] inputs, String loggedInUserName) {
//		LOGGER.info("\n LOGGED IN USERNAME:=====> " + loggedInUserName);
		for (String value : inputs) {
			if (StringUtils.isNotEmpty(value)) {
				for (Pattern checkpattern : patterns) {
					Matcher matcher = checkpattern.matcher(value.trim());
					if (matcher.matches()) {
//						LOGGER.error("\n\t\t INTRUSION OCCURED BY USER:>>>>>>>>> "
//								+ loggedInUserName
//								+ " <<<<<<<<<< WITH VALUE: "
//								+ value);
						System.out.println("class:  "+new Object(){}.getClass().getName()); // new Object().getClass().getEnclosingMethod())
						System.out.println("mehtod:  "+new Object(){}.getClass().getEnclosingMethod().getName());
						System.out.println("getclassname.methodname: "+getClass().getName());
						System.out.println("getclassname.methodname: "+IntrusionDetector.class.getEnclosingMethod());
						
							checkMethodName();
						
							System.out.println("\n\t\t INTRUSION OCCURED BY USER:>>>>>>>>> "
									+ loggedInUserName
									+ " <<<<<<<<<< WITH VALUE: "
									+ value);
							return true;

					}
				}
			}
		}
		return false;
	}


private void checkMethodName() {
//		System.out.println("name "+ getClass().getEnclosingMethod().toString());
	 StackTraceElement[] stacktrace = Thread.currentThread().getStackTrace();
	 StackTraceElement e = stacktrace[2];//maybe this number needs to be corrected
	 String methodName = e.getClassName();
	 
	 System.out.println("stackTrace method element: "+methodName);


		
	}


//	/**
//	 * @param value
//	 * @param loggedInUserName
//	 */
//	private void checkValues(String value, String loggedInUserName) {
//		
//		System.out.println("value: "+value);
//		if (!(value.equals(null))) {
//			for (Pattern checkpattern : patterns) {
//				System.out.println("patterns"+checkpattern.toString()+" value: "+value);
//				Matcher matcher = checkpattern.matcher(value);
//				if (matcher.matches()) {
//					// LOGGER.info("\n Intrusion occured and user is: "
//					// + loggedInUserName + " Value: " + value);
//					// throw new exception
//					System.out.println("MATCH FOUND....");
//
//				}
//
//			}
//		}
//
//	}

	public static void main(String[] args) {
		System.out.println("in main");
		IntrusionDetector detector = new IntrusionDetector();
		System.out.println("attacks: "+detector.checkAttacks(new String[] { "1=1"," qweda dsf ","<script>alert('hi');</script>", "javascript" }, "attacker"));
	}
}
