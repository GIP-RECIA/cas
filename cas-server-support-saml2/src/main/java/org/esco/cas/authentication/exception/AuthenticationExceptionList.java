/**
 * 
 */
package org.esco.cas.authentication.exception;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.springframework.util.CollectionUtils;

/**
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class AuthenticationExceptionList extends AuthenticationException {

	/** svUid. */
	private static final long serialVersionUID = 2832300041913587940L;

	private static final String CODE = "AuthenticationExceptionList";
	
	private static final String MESSAGE = "Multiple AuthenticationException were thrown ! The list of each one follow: \r\n";
	
	private final List<AuthenticationException> list = new ArrayList<AuthenticationException>();

	public AuthenticationExceptionList() {
		super(CODE);
	}

	public void add(AuthenticationException e) {
		if (e != null) {
			list.add(e);
		}
	}
	
	public List<AuthenticationException> getAll() {
		return list;
	}
	
	public boolean isEmpty() {
		return CollectionUtils.isEmpty(list);
	}

	@Override
	public String getLocalizedMessage() {
		StringBuilder sb = new StringBuilder(2048);
		sb.append(MESSAGE);
		for (Exception e : list) {
			sb.append(e.getLocalizedMessage());
		}
		return sb.toString();
	}

	@Override
	public String getMessage() {
		StringBuilder sb = new StringBuilder(2048);
		sb.append(MESSAGE);
		for (Exception e : list) {
			sb.append(e.getMessage());
		}
		return sb.toString();
	}

	@Override
	public StackTraceElement[] getStackTrace() {
		StackTraceElement[] fullStack = super.getStackTrace();
		for (Exception e : list) {
			fullStack = (StackTraceElement[]) ArrayUtils.addAll(fullStack, e.getStackTrace());
		}
		return fullStack;
	}

	@Override
	public void printStackTrace() {
		super.printStackTrace();
		for (Exception e : list) {
			e.printStackTrace();
		}
	}

	@Override
	public void printStackTrace(PrintStream s) {
		super.printStackTrace(s);
		for (Exception e : list) {
			e.printStackTrace(s);
		}
	}

	@Override
	public void printStackTrace(PrintWriter s) {
		super.printStackTrace(s);
		for (Exception e : list) {
			e.printStackTrace(s);
		}
	}

}
