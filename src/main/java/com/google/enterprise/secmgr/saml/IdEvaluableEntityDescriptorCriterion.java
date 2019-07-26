package com.google.enterprise.secmgr.saml;

import net.shibboleth.utilities.java.support.resolver.Criterion;
import org.opensaml.saml.metadata.criteria.entity.EvaluableEntityDescriptorCriterion;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

/**
 * Simple {@link EntityDescriptor} {@link Criterion} to match against ID.
 */
public class IdEvaluableEntityDescriptorCriterion implements EvaluableEntityDescriptorCriterion {

  private final String id;

  public IdEvaluableEntityDescriptorCriterion(String id) {
    this.id = id;
  }

  @Override
  public boolean apply(EntityDescriptor input) {
    return id.equals(input.getID());
  }
}
