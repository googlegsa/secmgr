package com.google.enterprise.sessionmanager;

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import java.io.IOException;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

@Singleton
public class SessionFilter implements Filter {

  @Inject
  private AuthnSessionManager sessionManager;

  private static final Logger logger = Logger.getLogger(SessionFilter.class.getName());

  @Override
  public void init(FilterConfig filterConfig) {

  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
      FilterChain filterChain) throws IOException, ServletException {

    filterChain.doFilter(servletRequest, servletResponse);

    afterServlet((HttpServletRequest) servletRequest);
  }

  @VisibleForTesting
  public void afterServlet(HttpServletRequest servletRequest) {
    HttpServletRequest httpRequest = servletRequest;
    AuthnSession authnSession = (AuthnSession) httpRequest.getAttribute("AuthnSession");
    if (authnSession == null) {
      logger.fine("No session, nothing to save");
      return;
    }
    if (authnSession.hasModifications()) {
      logger.fine("Saving modified session");
      authnSession.resetModifications();

      sessionManager.saveSession(authnSession);
    } else {
      sessionManager.updateSessionTTL(authnSession);
      logger.fine("No mods for session found, update ttl");
    }
  }

  @Override
  public void destroy() {

  }
}
